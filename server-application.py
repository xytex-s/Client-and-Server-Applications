#Receive the encrypted log file from the client and decrypt the log file using AES. It will then verify the hash of the log file to ensure integrity and store the log files securely.
import socket 
import hashlib
from threading import Thread
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

#Generate AES-256 key from password using PBKDF2 (same as client)
def generate_aes_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def decrypt_log(encrypted_content: bytes, key: bytes) -> bytes:
    iv = encrypted_content[:16]
    actual_encrypted_content = encrypted_content[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    data = decryptor.update(actual_encrypted_content) + decryptor.finalize()
    return data

def verify_log_hash(file_content: bytes, expected_hash: bytes) -> bool:
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    return sha256.digest() == expected_hash
    
def handle_client_connection(client_socket, client_addr):
    try:
        print(f"Handling connection from {client_addr}")
        
        received_data = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            received_data += chunk

        print(f"Received {len(received_data)} bytes")
        
        if len(received_data) < 16 + 32:
            print("Received data too small")
            return

        salt = received_data[:16]
        file_hash = received_data[-32:]
        encrypted_content = received_data[16:-32]
        
        print(f"Salt: {len(salt)} bytes, Hash: {len(file_hash)} bytes, Encrypted: {len(encrypted_content)} bytes")

        password = '%Pa55w0rd'
        aes_key = generate_aes_key(password, salt)

        try:
            file_content = decrypt_log(encrypted_content, aes_key)
            print(f"Decrypted content: {len(file_content)} bytes")
        except Exception as e:
            print(f"Decryption failed: {e}")
            return

        if not verify_log_hash(file_content, file_hash):
            print("File hash verification failed.")
            return

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = f"secure_log_{timestamp}.log"
        with open(filename, "wb") as f:
            f.write(file_content)
        print(f"Log file stored securely as {filename}")

    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        client_socket.close()
        
def start_server(host: str = '0.0.0.0', port: int = 2000): #ip and port to listen on for assessment
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            client_handler = Thread(target=handle_client_connection, args=(client_socket, addr))
            client_handler.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    start_server()
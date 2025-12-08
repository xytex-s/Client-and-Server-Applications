# Receive encrypted log file, decrypt, verify hash, store safely
import socket 
import hashlib
from threading import Thread
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


def generate_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def decrypt_log(encrypted_content, key):
    iv = encrypted_content[:16]
    actual_encrypted_content = encrypted_content[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(actual_encrypted_content) + decryptor.finalize()
    
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data


def verify_log_hash(file_content, expected_hash):
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    return sha256.digest() == expected_hash


def handle_client_connection(client_socket, client_addr):
    try:
        print("Handling connection from {}".format(client_addr))
        
        received_data = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            received_data += chunk

        print("Received {} bytes".format(len(received_data)))
        
        if len(received_data) < 48:
            print("Received data too small")
            return

        salt = received_data[:16]
        file_hash = received_data[-32:]
        encrypted_content = received_data[16:-32]
        
        print("Salt: {} bytes, Hash: {} bytes, Encrypted: {} bytes".format(
            len(salt), len(file_hash), len(encrypted_content)
        ))

        print("\n=== SERVER: Key Exchange Process ===")
        print("Received salt from client: {}...".format(salt.hex()[:32]))
        password = '%Pa55w0rd'
        print("Using password: {}".format('*' * len(password)))
        print("Deriving AES-256 key using PBKDF2-HMAC-SHA256...")
        aes_key = generate_aes_key(password, salt)
        print("Derived AES key: {}... (32 bytes)".format(aes_key.hex()[:32]))
        print("Key exchange complete - both sides have same symmetric key")
        print("===================================\n")

        try:
            file_content = decrypt_log(encrypted_content, aes_key)
            print("Decrypted content: {} bytes".format(len(file_content)))
        except Exception as e:
            print("Decryption failed: {}".format(e))
            return

        if not verify_log_hash(file_content, file_hash):
            print("File hash verification failed.")
            return

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = "secure_log_{}.log".format(timestamp)
        with open(filename, "wb") as f:
            f.write(file_content)
        
        try:
            os.chmod(filename, 0o600)
            if hasattr(os, 'chown'):
                os.chown(filename, 0, 0)
                print("Log file stored securely as {}".format(filename))
                print("File permissions set to root-only access")
            else:
                print("Log file stored as {}".format(filename))
                print("Root ownership not available on this platform")
        except PermissionError:
            print("Log file stored as {}".format(filename))
            print("Warning: Unable to set root ownership (run with sudo)")

    except Exception as e:
        print("Error handling client: {}".format(e))
    finally:
        client_socket.close()


def start_server(host='0.0.0.0', port=2000):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print("Server listening on {}:{}".format(host, port))

    try:
        while True:
            client_socket, addr = server_socket.accept()
            print("Accepted connection from {}".format(addr))
            client_handler = Thread(target=handle_client_connection, args=(client_socket, addr))
            client_handler.start()
    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
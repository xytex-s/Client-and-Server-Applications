import socket, sys, hashlib, threading
from threading import Thread
from socketserver import ThreadingMixIn
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

class Thread_of_Client(Thread):
    def __init__(self, client_socket, client_address):
        Thread.__init__(self)
        self.client_socket = client_socket
        self.client_address = client_address

    def run(self):
        print(f"Connection from {self.client_address} has been established.")
        while True:
            data = self.client_socket.recv(1024)
            if not data:
                break
            print(f"Received from {self.client_address}: {data.decode()}")
            self.client_socket.sendall(data)  # Echo back the received data
        self.client_socket.close()
        print(f"Connection from {self.client_address} has been closed.")
class ThreadedTCPServer(ThreadingMixIn, socket.socket):
    pass

SERVER_IP = '127.0.0.1'
SERVER_PORT = 2000
BUFFER_SIZE = 2048

def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(5)
    print(f"Server listening on {SERVER_IP}:{SERVER_PORT}")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            client_thread = Thread_of_Client(client_socket, client_address)
            client_thread.start()
    except KeyboardInterrupt:
        print("Server is shutting down.")
    finally:
        server_socket.close()

#Generate AES-256 key from password using PBKDF2
def generate_aes_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    return key

# Decrypt the file content using AES-256-CBC
def decrypt_file_content(encrypted_content: bytes, key: bytes) -> bytes:
    iv = encrypted_content[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_content[16:]) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

        
#Server-side program to receive and decrypt the file content using AES-256-CBC
def server_recieve_file(save_path, server_ip, server_port):
    password = b'securepassword'  # This should match the client's password
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)
    print(f"Server listening on {server_ip}:{server_port}")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr} has been established.")

    # Receive the salt
    salt = conn.recv(16)

    # Receive the encrypted file content
    encrypted_content = b""
    while True:
        data = conn.recv(BUFFER_SIZE)
        if not data:
            break
        encrypted_content += data
        
    # Generate AES key from password and received salt
    aes_key = generate_aes_key(password, salt)
    # Decrypt the file content
    decrypted_content = decrypt_file_content(encrypted_content, aes_key)
    # Save the decrypted content to a file
    with open(save_path, 'wb') as f:
        f.write(decrypted_content)
    print(f"Decrypted file saved to {save_path}")

    conn.close()
    server_socket.close()

    return salt, encrypted_content



if __name__ == "__main__":
    main()
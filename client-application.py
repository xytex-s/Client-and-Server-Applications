#Find Linux log files. Encrypt data with AES. Encrypt AES key with RSA. Digitally Sign with SHA-256. With Public key infrastructure.
import socket, sys, hashlib, os, time
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

#Find log files in /var/log
def find_log_files(directory="/var/log"):
    log_files = []
    if not os.path.exists(directory):
        print(f"Directory {directory} does not exist")
        return log_files
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".log") or file.endswith(".txt"):
                log_files.append(os.path.join(root, file))
    return log_files

#Generate AES-256 key from password using PBKDF2
def generate_aes_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password)

#Encrypt data with AES-256-CBC
def encrypt_file_content(file_content: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_content) + padder.finalize()
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_content

#Generate SHA-256 hash of file content
def generate_file_hash(file_content: bytes) -> bytes:
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    return sha256.digest()

#Send data to server
def send_data_to_server(server_ip: str, server_port: int, data: bytes):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, server_port))
        client_socket.sendall(data)
    finally:
        client_socket.close()
        
#Receive data from server
def receive_data_from_server(server_ip: str, server_port: int, buffer_size: int = 4096) -> bytes:
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, server_port))
        received_data = b""
        while True:
            chunk = client_socket.recv(buffer_size)
            if not chunk:
                break
            received_data += chunk
        return received_data
    finally:
        client_socket.close()
        
SERVER_IP = '127.0.0.1' #Change to server's IP if needed
SERVER_PORT = 2000 #Change to server's port if needed
BUFFER_SIZE = 4096

#Main function
def main():
    log_files = find_log_files()
    password = b'securepassword'  # Use a secure method to handle passwords
    salt = os.urandom(16)
    aes_key = generate_aes_key(password, salt)

    for log_file in log_files:
        with open(log_file, 'rb') as f:
            file_content = f.read()

        encrypted_content = encrypt_file_content(file_content, aes_key)
        file_hash = generate_file_hash(file_content)

        data_to_send = salt + encrypted_content + file_hash
        send_data_to_server(SERVER_IP, SERVER_PORT, data_to_send)

        print(f"Sent encrypted log file: {log_file}")
        
#Function to do this automatically when file hash changes
def monitor_and_send_logs(interval: int = 60):
    previous_hashes = {}
    while True:
        log_files = find_log_files()
        for log_file in log_files:
            with open(log_file, 'rb') as f:
                file_content = f.read()
            current_hash = generate_file_hash(file_content)

            if log_file not in previous_hashes or previous_hashes[log_file] != current_hash:
                password = b'securepassword'  # Use a secure method to handle passwords
                salt = os.urandom(16)
                aes_key = generate_aes_key(password, salt)

                encrypted_content = encrypt_file_content(file_content, aes_key)
                data_to_send = salt + encrypted_content + current_hash
                send_data_to_server(SERVER_IP, SERVER_PORT, data_to_send)

                print(f"Sent updated encrypted log file: {log_file}")
                previous_hashes[log_file] = current_hash
        time.sleep(interval)
        
#Function to allow for manual execution
def manual_send_logs():
    log_files = find_log_files()
    password = b'securepassword'  # Use a secure method to handle passwords
    salt = os.urandom(16)
    aes_key = generate_aes_key(password, salt)

    for log_file in log_files:
        with open(log_file, 'rb') as f:
            file_content = f.read()

        encrypted_content = encrypt_file_content(file_content, aes_key)
        file_hash = generate_file_hash(file_content)

        data_to_send = salt + encrypted_content + file_hash
        send_data_to_server(SERVER_IP, SERVER_PORT, data_to_send)

        print(f"Manually sent encrypted log file: {log_file}")
        
if __name__ == "__main__":
    monitor_and_send_logs()
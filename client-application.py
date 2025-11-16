# Find Linux log files. Encrypt data with AES. Encrypt AES key with RSA. 
import socket
import sys
import hashlib
import os
import time

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os


def discover_logs(directory="/var/log"):
    log_files = []
    if not os.path.exists(directory):
        print(f"Log files directory {directory} does not exist")
        return log_files
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".log") or file.endswith(".txt"):
                log_files.append(os.path.join(root, file))
    return log_files

def get_aes_key(password: str, salt: bytes) -> bytes:
	kdf = PBKDF2HMAC(
	algorithm=hashes.SHA256(),
	length=32,
	salt=salt,
	iterations=100000,
	backend=default_backend()
	)
	return kdf.derive(password.encode())

#Encrypt data with AES-256-CBC
def encrypt_log_content(file_content: bytes, key: bytes) -> bytes:
    iv = os.urandom(16) 
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    encrypted_content = encryptor.update(file_content) + encryptor.finalize()

    return iv + encrypted_content

def rsa_encrypt_aes_key(aes_key: bytes, public_key) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import serialization

    encrypted_key = public_key.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

#get certificate of log file content
def generate_log_hash(file_content: bytes) -> bytes:
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    return sha256.digest()

def send_log_to_server(server_ip: str, server_port: int, data: bytes):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, server_port))
        client_socket.sendall(data)
        print(f"Successfully sent {len(data)} bytes to server")
    except Exception as e:
        print(f"Error sending data to server: {e}")
    finally:
        client_socket.close()

def encrypt_and_send_log_file(log_file: str, password: str = '%Pa55w0rd') -> bool:
    try:
        with open(log_file, 'rb') as f:
            file_content = f.read()

        salt = os.urandom(16)
        aes_key = get_aes_key(password, salt)

        encrypted_content = encrypt_log_content(file_content, aes_key)
        file_hash = generate_log_hash(file_content)

        data_to_send = salt + encrypted_content + file_hash
        send_log_to_server(SERVER_IP, SERVER_PORT, data_to_send)
        
        return True
    except Exception as e:
        print(f"Error processing {log_file}: {e}")
        return False
        
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
    except Exception as e:
        print(f"Failed to receive data from server: {e}")
        return b""
    finally:
        client_socket.close()
        
SERVER_IP = '127.0.0.1'  # Change for assesment
SERVER_PORT = 2000       # Change for assessment  
BUFFER_SIZE = 4096

def main():
    log_files = discover_logs()
    if not log_files:
        print("No log files found!")
        return

    for log_file in log_files:
        if encrypt_and_send_log_file(log_file):
            print(f"Sent encrypted log file: {log_file}")
        else:
            print(f"Failed to send {log_file}")
        
def monitor_and_send_logs(interval: int = 60):
    previous_hashes = {}
    print(f"Starting log monitoring with {interval}s interval...")
    
    while True:
        log_files = discover_logs()
        for log_file in log_files:
            try:
                with open(log_file, 'rb') as f:
                    file_content = f.read()
                current_hash = generate_log_hash(file_content)

                if log_file not in previous_hashes or previous_hashes[log_file] != current_hash:
                    if encrypt_and_send_log_file(log_file):
                        print(f"Sent updated encrypted log file: {log_file}")
                        previous_hashes[log_file] = current_hash
                    else:
                        print(f"Failed to send updated log file: {log_file}")
            except FileNotFoundError:
                print(f"Warning: Log file {log_file} not found")
            except Exception as e:
                print(f"Error processing {log_file}: {e}")
                
        time.sleep(interval)
        
def manual_send_logs():
    log_files = discover_logs()
    print(f"Found {len(log_files)} log files to send...")
    
    for log_file in log_files:
        if encrypt_and_send_log_file(log_file):
            print(f"Manually sent encrypted log file: {log_file}")
        else:
            print(f"Failed to send {log_file}")
        
if __name__ == "__main__":
    print("Starting log monitoring service...")
    monitor_and_send_logs()
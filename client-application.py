# Find Linux log files. Encrypt data with AES. Encrypt AES key with RSA. 
import socket
import hashlib
import os
import time
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


def discover_logs(directory="/var/log"):
    log_files = []
    
    test_directory = "test-logs"
    if os.path.exists(test_directory):
        print("Found test log directory: {}".format(test_directory))
        for root, dirs, files in os.walk(test_directory):
            for file in files:
                if file.endswith(".log") or file.endswith(".txt"):
                    log_files.append(os.path.join(root, file))
    
    if not os.path.exists(directory):
        print("Log files directory {} does not exist".format(directory))
        return log_files

    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".log") or file.endswith(".txt"):
                log_files.append(os.path.join(root, file))
    return log_files


def get_aes_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_log_content(file_content, key):
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_content) + padder.finalize()
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()

    return iv + encrypted_content


def generate_log_hash(file_content):
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    return sha256.digest()


def send_log_to_server(server_ip, server_port, data):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((server_ip, server_port))
        client_socket.sendall(data)
        print("Successfully sent {} bytes to server".format(len(data)))
    except Exception as e:
        print("Error sending data to server: {}".format(e))
    finally:
        client_socket.close()


def encrypt_and_send_log_file(log_file, password='%Pa55w0rd'):
    try:
        with open(log_file, 'rb') as f:
            file_content = f.read()

        print("\n=== CLIENT: Key Exchange Process ===")
        salt = os.urandom(16)
        print("Generated salt: {}...".format(salt.hex()[:32]))
        print("Using password: {}".format('*' * len(password)))
        print("Deriving AES-256 key using PBKDF2-HMAC-SHA256...")
        aes_key = get_aes_key(password, salt)
        print("Derived AES key: {}... (32 bytes)".format(aes_key.hex()[:32]))
        print("Sending salt to server for key derivation")
        print("===================================\n")

        encrypted_content = encrypt_log_content(file_content, aes_key)
        file_hash = generate_log_hash(file_content)

        data_to_send = salt + encrypted_content + file_hash
        send_log_to_server(SERVER_IP, SERVER_PORT, data_to_send)
        
        return True
    except Exception as e:
        print("Error processing {}: {}".format(log_file, e))
        return False


SERVER_IP = '127.0.0.1'
SERVER_PORT = 2000
BUFFER_SIZE = 4096


def monitor_and_send_logs(interval=60):
    previous_hashes = {}
    last_sent_date = {}
    print("Starting log monitoring with {}s interval...".format(interval))
    print("Logs will be sent at 5:00 PM daily or when content changes")
    
    while True:
        log_files = discover_logs()
        current_time = datetime.now()
        current_date = current_time.date()
        current_hour = current_time.hour
        
        for log_file in log_files:
            try:
                with open(log_file, 'rb') as f:
                    file_content = f.read()
                current_hash = generate_log_hash(file_content)

                should_send_at_5pm = (current_hour == 17 and 
                                      last_sent_date.get(log_file) != current_date)
                
                hash_changed = (log_file not in previous_hashes or 
                                previous_hashes[log_file] != current_hash)
                
                if should_send_at_5pm or hash_changed:
                    if encrypt_and_send_log_file(log_file):
                        reason = []
                        if should_send_at_5pm:
                            reason.append("5 PM daily send")
                        if hash_changed:
                            reason.append("hash changed")
                        
                        print("Sent updated encrypted log file: {}".format(log_file))
                        if reason:
                            print("  Reason: {}".format(", ".join(reason)))

                        previous_hashes[log_file] = current_hash
                        if should_send_at_5pm:
                            last_sent_date[log_file] = current_date
                    else:
                        print("Failed to send updated log file: {}".format(log_file))
            except FileNotFoundError:
                print("Warning: Log file {} not found".format(log_file))
            except Exception as e:
                print("Error processing {}: {}".format(log_file, e))
                
        time.sleep(interval)


if __name__ == "__main__":
    print("Starting log monitoring service...")
    monitor_and_send_logs()

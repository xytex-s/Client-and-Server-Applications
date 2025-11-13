#Find Linux log files. Encrypt data with AES. Encrypt AES key with RSA. Digitally Sign with SHA-256. With Public key infrastructure.
import socket, sys, hashlib, os
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
    return iv + encrypted_content  # Prepend IV for decryption
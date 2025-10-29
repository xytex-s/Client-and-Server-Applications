import socket, sys, hashlib, os
from datetime import datetime

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os


SERVER_IP = input("Enter server IP address (default 127.0.0.1)")
SERVER_PORT = input("Enter server port (default 2000)")
BUFFER_SIZE = 2048

if not SERVER_IP:
    SERVER_IP = '127.0.0.1'
if not SERVER_PORT:
    SERVER_PORT = 2000
else:
    SERVER_PORT = int(SERVER_PORT)

    
# Generate AES-256 key from password using PBKDF2
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

# Encrypt the file content using AES-256-CBC
def encrypt_file_content(file_content: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(file_content) + padder.finalize()
    encrypted_content = encryptor.update(padded_data) + encryptor.finalize()
    return iv + encrypted_content  # Prepend IV for decryption

# Padding the plaintext to be a multiple of AES block size (128-bit / 16-byte)
def pad_data(data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    return padded_data

# Decrypt the file content using AES-256-CBC
def decrypt_file_content(encrypted_content: bytes, key: bytes) -> bytes:
    iv = encrypted_content[:16]
    actual_encrypted_content = encrypted_content[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(actual_encrypted_content) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Remove padding from the decrypted data
def unpad_data(padded_data: bytes) -> bytes:
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

# Encrypted AES Key using RSA 2048
def encrypt_aes_key(aes_key: bytes, public_key: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    public_key_obj = serialization.load_pem_public_key(public_key, backend=default_backend())
    if not isinstance(public_key_obj, rsa.RSAPublicKey):
        raise ValueError("Only RSA public keys are supported for encryption")
    
    encrypted_key = public_key_obj.encrypt(
        aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Add a hash for integrity check on the file SHA-256
def hash_file_content(file_content: bytes) -> bytes:
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    return sha256.digest()

# Client-side program to send encrypted file
def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    print(f"Connected to server at {SERVER_IP}:{SERVER_PORT}")

    password = b'%Pa55w0rd'  # In assessment, use a secure method to handle passwords
    salt = os.urandom(16)
    aes_key = generate_aes_key(password, salt)

    file_path = input("Enter the path of the file to send: ")
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()
            encrypted_content = encrypt_file_content(file_content, aes_key)

            # Send salt and encrypted content
            client_socket.sendall(salt + encrypted_content)
            print("File sent successfully.")
    except FileNotFoundError:
        print("File not found. Please check the path and try again.")
    finally:
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    main()
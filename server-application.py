#Server Application. It will recieve the encrypted log file from the client, decrypt the key using RSA and decrypt the log file using AES. 
# It will then verify the hash of the log file to ensure integrity and check the digital signature of each log file. then it will store the log files securely.
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

#Decrypt the key using RSA private key
def rsa_decrypt(encrypted_key: bytes, private_key) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import serialization

    decrypted_key = private_key.decrypt(
        encrypted_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

#Decrypt data with AES-256-CBC
def decrypt_file_content(encrypted_content: bytes, key: bytes) -> bytes:
    iv = encrypted_content[:16]
    actual_encrypted_content = encrypted_content[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(actual_encrypted_content) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data

#Verify SHA-256 hash of file content
def verify_file_hash(file_content: bytes, expected_hash: bytes) -> bool:
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    return sha256.digest() == expected_hash

#Verify digital signature
def verify_digital_signature(public_key, signature: bytes, data: bytes) -> bool:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature

    try:
        public_key.verify(
            signature,
            data,
            asym_padding.PSS(
                mgf=asym_padding.MGF1(hashes.SHA256()),
                salt_length=asym_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    
#Mulrithreaded server to handle multiple clients
class ThreadedTCPServer(ThreadingMixIn, socket.socket):
    pass

def handle_client_connection(client_socket, private_key, public_key):
    try:
        #Receive data from client
        received_data = b""
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            received_data += chunk

        #Extract encrypted key, encrypted content, hash, and signature
        encrypted_key = received_data[:256]  # Assuming RSA-2048
        encrypted_content = received_data[256:-64-256]  # Adjust based on actual sizes
        file_hash = received_data[-64-256:-256]
        signature = received_data[-256:]

        #Decrypt AES key
        aes_key = rsa_decrypt(encrypted_key, private_key)

        #Decrypt file content
        file_content = decrypt_file_content(encrypted_content, aes_key)

        #Verify file hash
        if not verify_file_hash(file_content, file_hash):
            print("File hash verification failed.")
            return

        #Verify digital signature
        if not verify_digital_signature(public_key, signature, file_content):
            print("Digital signature verification failed.")
            return

        #Store the log file securely
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        with open(f"secure_log_{timestamp}.log", "wb") as f:
            f.write(file_content)
        print("Log file stored securely.")

    finally:
        client_socket.close()
        
def start_server(host: str = '0.0.0.0', port: int = 12345, private_key=None, public_key=None):
    server = ThreadedTCPServer()
    server.bind((host, port))
    server.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, addr = server.accept()
        print(f"Accepted connection from {addr}")
        client_handler = Thread(target=handle_client_connection, args=(client_socket, private_key, public_key))
        client_handler.start()

if __name__ == "__main__":
    from cryptography.hazmat.primitives import serialization

    #Load RSA private key
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    #Load RSA public key
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    start_server(private_key=private_key, public_key=public_key)
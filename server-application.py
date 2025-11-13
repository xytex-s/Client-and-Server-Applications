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
    

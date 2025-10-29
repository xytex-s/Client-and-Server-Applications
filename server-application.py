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

# Decrypt AES Key using RSA 2048 private key
def decrypt_aes_key(encrypted_aes_key: bytes, private_key: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    private_key_obj = serialization.load_pem_private_key(
        private_key, 
        password=None, 
        backend=default_backend()
    )
    
    if not isinstance(private_key_obj, rsa.RSAPrivateKey):
        raise ValueError("Only RSA private keys are supported for decryption")
    
    decrypted_key = private_key_obj.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted_key

# Verify file integrity using SHA-256 hash
def verify_file_hash(file_content: bytes, received_hash: bytes) -> bool:
    sha256 = hashlib.sha256()
    sha256.update(file_content)
    calculated_hash = sha256.digest()
    return calculated_hash == received_hash

# Generate RSA key pair for the server
def generate_rsa_keypair():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Get public key and serialize to PEM format
    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    return private_key_pem, public_key_pem

        
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

#Server-side program to receive file with RSA-encrypted AES key and hash verification
def server_recieve_file_with_rsa(save_path, server_ip, server_port, private_key_pem):
    """
    Enhanced server to receive files encrypted with AES, where the AES key is encrypted with RSA,
    and includes SHA-256 hash verification for integrity checking.
    
    Protocol:
    1. Receive 256 bytes: RSA-encrypted AES key
    2. Receive 32 bytes: SHA-256 hash of original file
    3. Receive remaining bytes: IV + encrypted file content
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((server_ip, server_port))
    server_socket.listen(1)
    print(f"Server listening on {server_ip}:{server_port} (RSA mode)")

    conn, addr = server_socket.accept()
    print(f"Connection from {addr} has been established.")

    decrypted_content = None
    received_hash = None
    
    try:
        # Receive RSA-encrypted AES key (256 bytes for RSA-2048)
        encrypted_aes_key = conn.recv(256)
        if len(encrypted_aes_key) != 256:
            print(f"Warning: Expected 256 bytes for encrypted AES key, got {len(encrypted_aes_key)}")
        
        # Decrypt the AES key using server's RSA private key
        aes_key = decrypt_aes_key(encrypted_aes_key, private_key_pem)
        print(f"AES key decrypted successfully (length: {len(aes_key)} bytes)")
        
        # Receive SHA-256 hash of original file (32 bytes)
        received_hash = conn.recv(32)
        if len(received_hash) != 32:
            print(f"Warning: Expected 32 bytes for hash, got {len(received_hash)}")
        
        # Receive the encrypted file content (IV + encrypted data)
        encrypted_content = b""
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            encrypted_content += data
        
        print(f"Received {len(encrypted_content)} bytes of encrypted content")
        
        # Decrypt the file content
        decrypted_content = decrypt_file_content(encrypted_content, aes_key)
        print(f"File decrypted successfully ({len(decrypted_content)} bytes)")
        
        # Verify file integrity using SHA-256 hash
        if verify_file_hash(decrypted_content, received_hash):
            print("✓ File integrity verification successful!")
            
            # Save the decrypted content to a file
            with open(save_path, 'wb') as f:
                f.write(decrypted_content)
            print(f"Decrypted file saved to {save_path}")
            
            conn.sendall(b"SUCCESS: File received, decrypted, and verified")
        else:
            print("✗ File integrity verification FAILED!")
            conn.sendall(b"ERROR: File integrity verification failed")
            
    except Exception as e:
        print(f"Error during file reception: {e}")
        conn.sendall(f"ERROR: {str(e)}".encode())
    finally:
        conn.close()
        server_socket.close()

    # Return decrypted content only if both were successfully received and verified
    if decrypted_content is not None and received_hash is not None:
        return decrypted_content if verify_file_hash(decrypted_content, received_hash) else None
    return None



if __name__ == "__main__":
    main()
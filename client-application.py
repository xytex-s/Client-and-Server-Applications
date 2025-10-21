import socket, sys, hashlib
from datetime import datetime

SERVER_IP = input("Enter server IP address (default 127.0.0.1)")
SERVER_PORT = input("Enter server port (default 2000)")
BUFFER_SIZE = 2048

if not SERVER_IP:
    SERVER_IP = '127.0.0.1'
if not SERVER_PORT:
    SERVER_PORT = 2000
else:
    SERVER_PORT = int(SERVER_PORT)

def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((SERVER_IP, SERVER_PORT))
        print(f"Connected to server at {SERVER_IP}:{SERVER_PORT}")

        while True:
            message = input("Enter message to send (or 'exit' to quit): ")
            if message.lower() == 'exit':
                break
            client_socket.sendall(message.encode())
            data = client_socket.recv(BUFFER_SIZE)
            print(f"Received from server: {data.decode()}")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        client_socket.close()
        print("Connection closed.")

if __name__ == "__main__":
    main()
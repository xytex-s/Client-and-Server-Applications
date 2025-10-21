import socket, sys, hashlib, threading
from threading import Thread
from socketserver import ThreadingMixIn
from datetime import datetime

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

if __name__ == "__main__":
    main()
import socket
import threading

SERVER_IP = "100.92.71.62"
PORT = 5000

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, PORT))

lock = threading.Lock()

def receive_messages():
    while True:
        data = client_socket.recv(1024)
        if not data:
            break
        with lock:
            print(f"\n[PC1] {data.decode()}\n[PC2] ", end="")

def send_messages():
    while True:
        message = input("[PC2] ")
        with lock:
            client_socket.sendall(message.encode())

threading.Thread(target=receive_messages, daemon=True).start()
send_messages()
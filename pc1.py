import socket
import threading

SERVER_IP = "100.92.71.62"
PORT = 5000

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_IP, PORT))
server_socket.listen(1)

print(f"[PC1] Listening on {SERVER_IP}:{PORT}")

conn, addr = server_socket.accept()
print(f"[PC1] Connected by {addr}")

lock = threading.Lock()

def receive_messages():
    while True:
        data = conn.recv(1024)
        if not data:
            break
        with lock:
            print(f"\n[PC2] {data.decode()}\n[PC1] ", end="")

def send_messages():
    while True:
        message = input("[PC1] ")
        with lock:
            conn.sendall(message.encode())

threading.Thread(target=receive_messages, daemon=True).start()
send_messages()
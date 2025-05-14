import socket
import threading
from rejndael import aes, TEST_KEYS

# 100.102.137.18 - zaco
SERVER_IP = "100.102.137.18"
PORT = 5000

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, PORT))

lock = threading.Lock()

def receive_messages():
    while True:
        # encrypted_msg = client_socket.recv(1024)
        # decrypted_msg = aes(bytearray(encrypted_msg), cypher_type="aes_128", key=TEST_KEYS["aes_128"][0], decrypt=True)
        # if not decrypted_msg:
        #     break
        # with lock:
        #     print(f"\n[PC1] {decrypted_msg}\n[PC2] ",end = "")

        data = client_socket.recv(1024)
        if not data:
            break
        with lock:
            print(f"\n[PC1] {data.decode()}\n[PC2] ", end="")

def send_messages():
    while True:
        # message = input("[PC2] ")
        # encrypted_msg = aes(message, cypher_type="aes_128", key=TEST_KEYS["aes_128"][0])
        # with lock:
        #     client_socket.sendall(encrypted_msg)

        message = input("[PC2] ")
        with lock:
            client_socket.sendall(message.encode())

threading.Thread(target=receive_messages, daemon=True).start()
send_messages()
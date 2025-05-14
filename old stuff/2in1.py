import socket
import threading
import time

from rejndael import aes, TEST_KEYS

# === CONFIGURE CONNECTION ===
PEER_IP = "100.102.137.18"  # Replace with actual peer IP
SEND_PORT = 5000
RECV_PORT = 5001
lock = threading.Lock()

# === SETUP SOCKETS ===
recv_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connected = False
server_mode = False  # Track if this peer becomes the server

# === ATTEMPT TO CONNECT FIRST ===
while not connected:
    try:
        print(f"[TRYING] Connecting to peer at {PEER_IP}:{SEND_PORT}...")
        send_socket.connect((PEER_IP, SEND_PORT))
        connected = True
        print(f"[CONNECTED] Sending messages to {PEER_IP}:{SEND_PORT}")
    except (ConnectionRefusedError, OSError):
        print("[FAILED] Connection refused, switching to server mode...")
        server_mode = True
        break  # Exit loop to start listening

# === IF CONNECTION FAILED, LISTEN INSTEAD ===
if server_mode:
    recv_socket.bind(("0.0.0.0", RECV_PORT))
    recv_socket.listen(1)
    print(f"[LISTENING] Waiting for connection on port {RECV_PORT}...")
    conn, addr = recv_socket.accept()
    print(f"[CONNECTED] Receiving messages from {addr}")

    # Swap roles: now use 'conn' to send messages
    send_socket, conn = conn, send_socket


# === RECEIVING THREAD ===
def receive_messages():
    while True:
        try:
            encrypted_msg = conn.recv(1024)
            if not encrypted_msg:
                print("[DISCONNECTED] Peer closed connection.")
                break
            decrypted_msg = aes(bytearray(encrypted_msg), cypher_type="aes_128", key=TEST_KEYS["aes_128"][0], decrypt=True)
            with lock:
                print(f"\n[PEER] {decrypted_msg}\n[YOU] ", end="")
        except Exception as e:
            print(f"[ERROR] Receiving failed: {e}")
            break


# === SENDING FUNCTION ===
def send_messages():
    while True:
        try:
            message = input("[YOU] ")
            encrypted_msg = aes(message, cypher_type="aes_128", key=TEST_KEYS["aes_128"][0])
            with lock:
                send_socket.sendall(encrypted_msg)
        except Exception as e:
            print(f"[ERROR] Sending failed: {e}")
            break


# Start receiving messages in a separate thread
threading.Thread(target=receive_messages, daemon=True).start()
send_messages()

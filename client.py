import socket
import websockets

# IP of the server machine (Tailscale IP)
SERVER_IP = "100.81.251.117"  # Change this to match the server's Tailscale IP
PORT = 5000

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((SERVER_IP, PORT))

message = "Hello from the Tailscale client!"
client_socket.sendall(message.encode())

response = client_socket.recv(1024)
print(f"Server response: {response.decode()}")

client_socket.close()

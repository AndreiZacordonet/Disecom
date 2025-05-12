import random
import sys
import socket
import threading
from rejndael import aes, TEST_KEYS


class StationNetwork:
    def __init__(self, message_callback=None, status_callback=None, bind_ip="127.0.0.1", bind_port=5000):
        self.message_callback = message_callback or (lambda h, m: None)
        self.status_callback = status_callback or (lambda h, s, e=None: None)
        self.connections = {}  # {hostname: (socket, address)}
        self.lock = threading.Lock()
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.listen_socket = None
        self.start_listening()

    def start_listening(self):
        try:
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind((self.bind_ip, self.bind_port))
            self.listen_socket.listen(5)
            threading.Thread(target=self.accept_connections, daemon=True).start()
        except Exception as e:
            raise Exception(f"Could not start listening: {e}")

    def accept_connections(self):
        while True:
            try:
                client_socket, address = self.listen_socket.accept()
                hostname = f"{address[0]}:{address[1]}"
                with self.lock:
                    if hostname not in self.connections:
                        self.connections[hostname] = (client_socket, address)
                        self.status_callback(hostname, "connected")
                        threading.Thread(target=self.receive_messages, args=(client_socket, hostname), daemon=True).start()
            except Exception as e:
                print(f"Accept error: {e}")

    def connect_to_peer(self, hostname):
        try:
            if hostname in self.connections:
                return
            ip, port = hostname.split(":")
            port = int(port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))
            sock.settimeout(None)
            with self.lock:
                self.connections[hostname] = (sock, (ip, port))
                threading.Thread(target=self.receive_messages, args=(sock, hostname), daemon=True).start()
                self.status_callback(hostname, "connected")
        except Exception as e:
            self.status_callback(hostname, "error", str(e))
            raise

    def receive_messages(self, sock, hostname):
        try:
            while True:
                data = sock.recv(1024)
                if not data:
                    break
                try:
                    decrypted = aes(bytearray(data), cypher_type="aes_128", key=TEST_KEYS["aes_128"][0], decrypt=True)
                    self.message_callback(hostname, decrypted)
                except Exception as e:
                    print(f"Decrypt error from {hostname}: {e}")
        except Exception as e:
            print(f"Socket error with {hostname}: {e}")
        finally:
            try: sock.close()
            except: pass
            with self.lock:
                if hostname in self.connections:
                    del self.connections[hostname]
                    self.status_callback(hostname, "disconnected")

    def send_message(self, hostname, message):
        if not message or hostname not in self.connections:
            return False
        try:
            encrypted = aes(str(message), cypher_type="aes_128", key=TEST_KEYS["aes_128"][0])
            with self.lock:
                sock, _ = self.connections[hostname]
                sock.sendall(encrypted)
            return True
        except Exception as e:
            print(f"Send error to {hostname}: {e}")
            with self.lock:
                if hostname in self.connections:
                    del self.connections[hostname]
            self.status_callback(hostname, "disconnected")
            return False

    def get_connected_peers(self):
        with self.lock:
            return list(self.connections.keys())

peer_keys = {}
my_secret = random.getrandbits(1024)

def main():
    if len(sys.argv) < 3:
        print("Usage: python peer_client.py <bind_port> <peer_ip>:<peer_port>")
        sys.exit(1)

    bind_port = int(sys.argv[1])
    peer_info = sys.argv[2]
    peer_ip, peer_port = peer_info.split(":")
    peer_port = int(peer_port)

    my_hostname = f"localhost:{bind_port}"
    peer_hostname = f"{peer_ip}:{peer_port}"

    def on_message_received(hostname, message):
        print(f"\n[{hostname}] {message}\n> ", end="")

    def on_connection_status(hostname, status, error=None):
        if status == "connected":
            print(f"[INFO] Connected to {hostname}")
        elif status == "disconnected":
            print(f"[INFO] Disconnected from {hostname}")
        elif status == "error":
            print(f"[ERROR] {hostname}: {error}")

    network = StationNetwork(
        message_callback=on_message_received,
        status_callback=on_connection_status,
        bind_ip="127.0.0.1",
        bind_port=bind_port
    )

    try:
        network.connect_to_peer(peer_hostname)
    except Exception as e:
        print(f"[ERROR] Could not connect: {e}")
        sys.exit(1)

    def input_loop():
        while True:
            try:
                msg = input("> ")
                if msg.strip().lower() == "exit":
                    break
                if not network.send_message(peer_hostname, msg):
                    print("[ERROR] Failed to send message")
            except KeyboardInterrupt:
                break
        print("Exiting...")

    input_thread = threading.Thread(target=input_loop, daemon=False)
    input_thread.start()
    input_thread.join()


if __name__ == "__main__":
    main()

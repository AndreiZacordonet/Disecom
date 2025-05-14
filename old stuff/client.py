import random
import secrets
import sys
import socket
import threading

from message import create_halfway_key, P, G, pack_key_gen_message, pack_text_message, unpack_message, create_key
from rejndael import aes, TEST_KEYS


class StationNetwork:
    def __init__(self, message_callback=None, status_callback=None, bind_ip="127.0.0.1", bind_port=5000, secret: int = None):
        self.message_callback = message_callback or (lambda h, m: None)
        self.status_callback = status_callback or (lambda h, s, e=None: None)
        self.connections = {}
        self.lock = threading.Lock()
        self.bind_ip = bind_ip
        self.bind_port = bind_port
        self.listen_socket = None
        self.start_listening()
        self.secret = secret
        self.shared_keys = {}

    def start_listening(self):
        try:
            # TODO: make it listen as long as it needs
            self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listen_socket.bind((self.bind_ip, self.bind_port))
            self.listen_socket.listen(5)
            threading.Thread(target=self.accept_connections, daemon=True).start()
        except Exception as e:
            raise Exception(f"Could not start listening: {e}")

    # def accept_connections(self):
    #     while True:
    #         try:
    #             client_socket, address = self.listen_socket.accept()
    #             hostname = f"{address[0]}:{address[1]}"
    #             with self.lock:
    #                 if hostname not in self.connections:
    #                     self.connections[hostname] = (client_socket, address)
    #                     print(f'{self.connections=}')
    #                     self.status_callback(hostname, "connected")
    #                     threading.Thread(target=self.receive_messages, args=(client_socket, hostname), daemon=True).start()
    #         except Exception as e:
    #             print(f"Accept error: {e}")
    def accept_connections(self):
        while True:
            try:
                client_socket, address = self.listen_socket.accept()

                # Step 1: receive peer's identity
                identity = client_socket.recv(64).decode().strip()
                hostname = identity  # e.g., "127.0.0.1:5001"

                with self.lock:
                    if hostname not in self.connections:
                        self.connections[hostname] = (client_socket, address)
                        print(f'{self.connections=}')
                        self.status_callback(hostname, "connected")
                        threading.Thread(target=self.receive_messages, args=(client_socket, hostname),
                                         daemon=True).start()
            except Exception as e:
                print(f"Accept error: {e}")

    def connect_to_peer(self, hostname):
        try:
            if hostname in self.connections:
                return
            ip, port = hostname.split(":")
            port = int(port)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((ip, port))
            sock.settimeout(None)

            # Step 2: send our own identity (e.g., "127.0.0.1:5001")
            identity = f"{self.bind_ip}:{self.bind_port}"
            sock.sendall(identity.encode().ljust(64, b' '))  # pad to fixed length

            with self.lock:
                self.connections[hostname] = (sock, (ip, port))
                threading.Thread(target=self.receive_messages, args=(sock, hostname), daemon=True).start()
                self.status_callback(hostname, "connected")

            # Trimite cheia halfway imediat după conectare
            halfway_key = create_halfway_key(P, G, self.secret)
            msg = pack_key_gen_message(halfway_key)
            sock.sendall(msg)
        except Exception as e:
            self.status_callback(hostname, "error", str(e))
            raise

    def receive_messages(self, sock, hostname):
        try:
            while True:
                data = sock.recv(4096)
                if not data:
                    break

                # Deserializare mesaj
                msg = unpack_message(data)
                if not msg:
                    print(f"[WARN] Unknown/invalid message from {hostname}")
                    continue

                msg_type = msg.get('type')
                if msg_type == 'KEY_GEN':
                    # Peer-ul trimite cheia sa halfway
                    halfway_key = msg['halfway_key']
                    # Calculează cheia comună
                    shared_key = create_key(P, self.secret, halfway_key)
                    self.shared_keys[hostname] = shared_key
                    print(f"[INFO] Shared key established with {hostname}")
                elif msg_type == 'TEXT_MSG':
                    if hostname not in self.shared_keys:
                        print(f"[WARN] No shared key with {hostname}. Cannot decrypt message.")
                        continue
                    shared_key = self.shared_keys[hostname]
                    encrypted = msg['payload']
                    try:
                        # Decriptează mesajul text
                        decrypted = aes(encrypted.decode(), cypher_type="aes_128", key=shared_key, decrypt=True)
                        self.message_callback(hostname, decrypted)
                    except Exception as e:
                        print(f"Decrypt error from {hostname}: {e}")
                elif msg_type == 'FILE_BLOCK':
                    # Placeholder pentru salvare bloc fișier
                    print(f"[INFO] Received file block from {hostname} (file: {msg['file_name']}, block: {msg['block_number']})")
                    # TODO: apelează aici funcția ta de salvare a blocului de fișier
                else:
                    print(f"[WARN] Received unknown message type from {hostname}: {msg_type}")
        except Exception as e:
            print(f"Socket error with {hostname}: {e}")
        finally:
            try: sock.close()
            except: pass
            with self.lock:
                if hostname in self.connections:
                    del self.connections[hostname]
                    self.status_callback(hostname, "disconnected")

    def send_message(self, hostname, data, msg_type: str):

        if not data or hostname not in self.connections:
            return False

        def send_one_message(message):
            nonlocal self, hostname
            try:
                with self.lock:
                    sock, _ = self.connections[hostname]
                    sock.sendall(message)
                return True
            except Exception as e:
                print(f"Send error to {hostname}: {e}")
                with self.lock:
                    if hostname in self.connections:
                        del self.connections[hostname]
                self.status_callback(hostname, "disconnected")
                return False

        output_status = None

        match msg_type:
            case 'FILE_BLOCK':
                pass
            case 'KEY_GEN':
                msg = pack_key_gen_message(data)
                output_status = send_one_message(msg)
            case 'TEXT_MSG':
                if hostname not in self.shared_keys:
                    print(f"[WARN] No shared key with {hostname}. Cannot send encrypted message.")
                    return False
                shared_key = self.shared_keys[hostname]
                encrypted = aes(str(data), cypher_type="aes_128", key=shared_key)
                msg = pack_text_message(encrypted)
                output_status = send_one_message(msg)

        return output_status

    def get_connected_peers(self):
        with self.lock:
            return list(self.connections.keys())


peer_keys = {}
my_secret = random.getrandbits(1024)


def app(my_port: int, p_ip: str, p_port: int):

    bind_port = my_port
    peer_ip, peer_port = p_ip, p_port

    peer_hostname = f"{peer_ip}:{peer_port}"

    # generate client halfway key
    secret = secrets.randbits(128)
    halfway_key = create_halfway_key(P, G, secret)

    def on_message_received(hostname, message):
        print(f"\n[{hostname}] {message}\n> ", end="")

    def on_connection_status(hostname, status, error=None):
        if status == "connected":
            print(f"[INFO] Connected to {hostname}")
            # send halfway key to peer
            network.send_message(peer_hostname, halfway_key, 'KEY_GEN')
        elif status == "disconnected":
            print(f"[INFO] Disconnected from {hostname}")
        elif status == "error":
            print(f"[ERROR] {hostname}: {error}")

    network = StationNetwork(
        message_callback=on_message_received,
        status_callback=on_connection_status,
        bind_ip="127.0.0.1",
        bind_port=bind_port,
        secret=secret
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
                if not network.send_message(peer_hostname, msg, 'TEXT_MSG'):
                    print("[ERROR] Failed to send message")
            except KeyboardInterrupt:
                break
        print("Exiting...")

    input_thread = threading.Thread(target=input_loop, daemon=False)
    input_thread.start()
    input_thread.join()

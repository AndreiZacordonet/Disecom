import asyncio
import websockets
import threading

MY_IP = "100.102.137.18"  # IP-ul Tailscale al stației tale
PEER_IP = "100.81.251.117"  # IP-ul celeilalte stații
PORT = 5000

# Funcția pentru a primi mesaje (server)
async def handler(websocket, _):
    while True:
        try:
            message = await websocket.recv()
            print(f"[Received] {message}")
        except websockets.ConnectionClosed:
            print("[Server] Connection closed.")
            break

async def receive_messages():
    server = await websockets.serve(handler, MY_IP, PORT)
    print(f"Listening on ws://{MY_IP}:{PORT}")
    await server.wait_closed()

# Funcția pentru a trimite mesaje (client)
async def send_messages():
    async with websockets.connect(f"ws://{PEER_IP}:{PORT}") as websocket:
        while True:
            message = input("Enter message: ")
            await websocket.send(message)

# Pornim serverul și clientul simultan
def start():
    threading.Thread(target=lambda: asyncio.run(receive_messages()), daemon=True).start()
    asyncio.run(send_messages())

start()
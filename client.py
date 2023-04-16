import socket
import threading
from constants import HOST, PORT
from message import send, recv

# create the client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to the server:
print(f"[+] Connecting to {HOST}:{PORT}")
client.connect((HOST, PORT))
print("[+] Connected.")

threading.Thread(target=send, args=(client,)).start()
threading.Thread(target=recv(client, (HOST, PORT)), args=(client,)).start()

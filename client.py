import socket
import threading
from constants import HOST, PORT, SEPARATOR, PUBLIC_KEY
from message import send, recv
from utils import init_keys

# create the client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to the server:
print(f"[+] Connecting to {HOST}:{PORT}")
client.connect((HOST, PORT))
print("[+] Connected.")
# type password
password = input("Password: ")
public_key, private_key = init_keys(PORT, password)
client.send(f"{PUBLIC_KEY}{SEPARATOR}{public_key}".encode())

threading.Thread(target=send, args=(client,)).start()
threading.Thread(target=recv(client, (HOST, PORT)), args=(client,)).start()

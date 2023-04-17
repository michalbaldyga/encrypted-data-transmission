import socket
import threading
from constants import HOST, PORT, PORT2
from cryptography import assign_rsa_keys
from message import send, recv
from utils import login

# create the client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bind the socket to our local address
client.bind((HOST, PORT2))

# connect to the server:
print(f"[+] Connecting to {HOST}:{PORT}")
client.connect((HOST, PORT))
print("[+] Connected.")

# login/registration
hash_password = login(PORT2)

# generate public and private key
public_key, private_key = assign_rsa_keys(str(PORT2), hash_password)

# send public key to other user
# client.send(public_key.encode())

# recv other user public key
# received_key = client.recv(BUFFER_SIZE).decode()

threading.Thread(target=send, args=(client,)).start()
threading.Thread(target=recv(client, PORT, PORT2), args=(client,)).start()

import socket
import threading
from constants import HOST, PORT, PORT2
from crypto import assign_rsa_keys, recv_public_key, create_session_key, send_session_key
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

# Generate RSA public and private key for client
private_key, public_key = assign_rsa_keys(str(PORT2), hash_password)

# Receive from the server the RSA public key
received_pub_key_ = recv_public_key(client)

# Create, encrypt using received public key and send session key to the server
session_key = create_session_key()
send_session_key(client, received_pub_key_, session_key)

# create threads for receiving and sending messages
threading.Thread(target=send, args=(client, session_key)).start()
threading.Thread(target=recv, args=(client, PORT, PORT2, session_key,)).start()

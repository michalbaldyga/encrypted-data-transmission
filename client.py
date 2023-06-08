import socket
import threading
from constants import HOST, PORT, PORT2
from crypto import assign_rsa_keys, send_public_key, recv_public_key, create_session_key, send_session_key
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
private_key, public_key = assign_rsa_keys(str(PORT2), hash_password)

# exchanging the public keys
send_public_key(client, public_key)
recvied_pub_key_ = recv_public_key(client)

# create and send session key -> one for transmission
session_key = create_session_key()
send_session_key(client, recvied_pub_key_, session_key)

threading.Thread(target=send, args=(client, session_key)).start()
threading.Thread(target=recv, args=(client, PORT, PORT2, session_key,)).start()

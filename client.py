import socket
import threading
from constants import HOST, PORT, PORT2
from crypto import assign_rsa_keys, send_public_key, recv_public_key, create_session_key
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

# TODO create a session key and send it

session_key = create_session_key(recvied_pub_key_)

threading.Thread(target=send, args=(client, recvied_pub_key_)).start()
threading.Thread(target=recv(client, PORT, PORT2, private_key), args=(client,)).start()

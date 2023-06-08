import threading
import socket
from constants import HOST, PORT, PORT2
from crypto import assign_rsa_keys, send_public_key, recv_public_key, recv_session_key
from message import send, recv
from utils import login

# create the server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bind the socket to our local address
server.bind((HOST, PORT))

# enabling our server to accept connections
server.listen()
print(f"[*] Listening as {HOST}:{PORT}")

# accept connection if there is any
client, address = server.accept()
print(f"[+] {address} is connected.")

# login/registration
hash_password = login(PORT)

# generate public and private key
private_key, public_key = assign_rsa_keys(str(PORT), hash_password)

# exchanging the public keys
send_public_key(client, public_key)
recvied_pub_key_ = recv_public_key(client)

# receive the session key -> one for transmission
session_key = recv_session_key(client, private_key)

threading.Thread(target=send, args=(client, session_key,)).start()
threading.Thread(target=recv, args=(client, PORT2, PORT, session_key,)).start()

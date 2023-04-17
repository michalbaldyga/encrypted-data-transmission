import threading
import socket
from constants import HOST, PORT, BUFFER_SIZE, MESSAGE_TAG, SEPARATOR, FILE_TAG, PUBLIC_KEY, PORT2
from message import send, recv
from utils import init_keys, login

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
public_key, private_key = init_keys(str(PORT), hash_password)

# send public key to other user
# client.send(public_key.encode())

# recv other user public key
# received_key = client.recv(BUFFER_SIZE).decode()

threading.Thread(target=send, args=(client,)).start()
threading.Thread(target=recv(client, PORT2, PORT), args=(client,)).start()

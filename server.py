import threading
import socket
from constants import HOST, PORT, PORT2
from cryptography import assign_rsa_keys
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

public_key, private_key = assign_rsa_keys(str(PORT), hash_password)


# send public key to other user
# client.send(public_key.encode())

# recv other user public key
# received_key = client.recv(BUFFER_SIZE).decode()

threading.Thread(target=send, args=(client,)).start()
threading.Thread(target=recv(client, PORT2, PORT), args=(client,)).start()

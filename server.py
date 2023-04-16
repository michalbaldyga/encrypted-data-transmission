import threading
import socket
from constants import HOST, PORT, BUFFER_SIZE, MESSAGE_TAG, SEPARATOR, FILE_TAG, PUBLIC_KEY
from message import send, recv
from utils import init_keys

# create the server socket
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# bind the socket to our local address
server.bind((HOST, PORT))

# enabling our server to accept connections
server.listen()
print(f"[*] Listening as {HOST}:{PORT}")
# type password
password = input("Password: ")
# accept connection if there is any
client, address = server.accept()
print(f"[+] {address} is connected.")
public_key, private_key = init_keys(address[1], password)
client.send(f"{PUBLIC_KEY}{SEPARATOR}{public_key}".encode())
threading.Thread(target=send, args=(client,)).start()
threading.Thread(target=recv(client, address), args=(client,)).start()

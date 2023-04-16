import threading
import socket
from constants import HOST, PORT, BUFFER_SIZE, MESSAGE_TAG, SEPARATOR, FILE_TAG
from message import send, recv

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

threading.Thread(target=send, args=(client,)).start()
threading.Thread(target=recv(client, address), args=(client,)).start()

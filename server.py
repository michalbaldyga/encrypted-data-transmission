import os
import socket
import threading
from message import sending_messages, receiving_messages
from constants import *

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

# receive the file infos
received = client.recv(BUFFER_SIZE).decode()
filename, filesize = received.split(SEPARATOR)

# remove absolute path if there is
filename = "new_" + os.path.basename(filename)
# convert to integer
filesize = int(filesize)

# start receiving the file from the socket and writing to the file stream
with open(filename, "wb") as f:
    while True:
        # read 1024 bytes from the socket (receive)
        bytes_read = client.recv(BUFFER_SIZE)
        if not bytes_read:
            # nothing is received file transmitting is done
            break
        # write to the file the bytes we just received
        f.write(bytes_read)

client.close()
server.close()

import os
import socket
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

while True:
    eof = False
    received = client.recv(BUFFER_SIZE).decode()
    info = received.split(SEPARATOR)
    if info[0] == MESSAGE_TAG:
        print(info[1])
    elif info[0] == FILE_TAG:
        filename, filesize = info[1], info[2]
        filename = "new_" + os.path.basename(filename)
        filesize = int(filesize)
        # start receiving the file from the socket and writing to the file stream
        with open(filename, "wb") as f:
            while True:
                # read 1024 bytes from the socket (receive)
                bytes_read = client.recv(BUFFER_SIZE)
                if bytes_read.endswith(b"<END>"):
                    eof = True
                if eof:
                    f.write(bytes_read[:-5])
                    f.flush()
                    break
                else:
                    f.write(bytes_read)

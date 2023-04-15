import os
import socket
import threading
from message import sending_messages, receiving_messages
from constants import *

# create the client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to the server:
print(f"[+] Connecting to {HOST}:{PORT}")
client.connect((HOST, PORT))
print("[+] Connected.")

# send the filename and filesize
filename = "fota.png"
filesize = os.path.getsize(filename)
client.send(f"{filename}{SEPARATOR}{filesize}".encode())

# send the file
with open(filename, "rb") as f:
    while True:
        # read the bytes from the file
        bytes_read = f.read(BUFFER_SIZE)
        if not bytes_read:
            # file transmitting is done
            break
        # we use sendall to assure transmission in busy networks
        client.sendall(bytes_read)

client.close()

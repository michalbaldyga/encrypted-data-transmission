import socket
from constants import *
import os

# create the client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to the server:
print(f"[+] Connecting to {HOST}:{PORT}")
client.connect((HOST, PORT))
print("[+] Connected.")

while True:
    option = input("1.Send message\n2.Send file\n3.Exit\nChoose option: ")

    # Message
    if option == "1":
        message = input("Message: ")
        client.send(f"{MESSAGE_TAG}{SEPARATOR}{message}".encode())

    # File
    elif option == "2":
        # send the filename and filesize
        filename = input("Filename: ")
        filesize = os.path.getsize(filename)
        client.send(f"{FILE_TAG}{SEPARATOR}{filename}{SEPARATOR}{filesize}".encode())
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
        client.send("<END>".encode())

    else:
        client.close()
        break

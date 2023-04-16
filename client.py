import socket
from constants import *
import os
from message import send_file

# create the client socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to the server:
print(f"[+] Connecting to {HOST}:{PORT}")
client.connect((HOST, PORT))
print("[+] Connected.")

while True:
    option = input("1.Send message\n2.Send file\n3.Exit\nChoose option: ")

    # send message
    if option == "1":
        message = input("Message: ")
        client.send(f"{MESSAGE_TAG}{SEPARATOR}{message}".encode())

    # send file
    elif option == "2":
        # send the filename and filesize
        filename = input("Filename: ")
        filesize = os.path.getsize(filename)
        client.send(f"{FILE_TAG}{SEPARATOR}{filename}{SEPARATOR}{filesize}".encode())
        send_file(filename, filesize, client)

    # exit
    else:
        client.close()
        break

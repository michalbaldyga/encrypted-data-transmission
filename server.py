import os
import socket
from constants import HOST, PORT, BUFFER_SIZE, MESSAGE_TAG, SEPARATOR, FILE_TAG
from message import recv_file

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

# start receiving data from the socket
while True:
    received = client.recv(BUFFER_SIZE).decode()
    data_info = received.split(SEPARATOR)
    # recv message
    if data_info[0] == MESSAGE_TAG:
        print("Message: " + data_info[1])
    # recv file
    elif data_info[0] == FILE_TAG:
        filename = "./new_files/" + os.path.basename(data_info[1])
        filesize = int(data_info[2])
        recv_file(filename, filesize, client)

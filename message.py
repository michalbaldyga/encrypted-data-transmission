import socket
import os
from constants import *


def recv_file(filename: str, filesize: int, conn: socket.socket):
    """receiving the file from the socket and writing to the file stream"""
    with open(filename, "wb") as f:
        while True:
            bytes_read = conn.recv(BUFFER_SIZE)
            if bytes_read.endswith(END_TAG.encode()):
                # file transmitting is done
                f.write(bytes_read[:-len(END_TAG)])
                f.flush()
                break
            else:
                f.write(bytes_read)


def send_file(filename: str, filesize: int, conn: socket.socket):
    """sending the file"""
    with open(filename, "rb") as f:
        while True:
            # read the bytes from the file
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                # file transmitting is done
                break
            conn.sendall(bytes_read)
    conn.send("<END>".encode())


def send(client: socket.socket):
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


def recv(client: socket.socket, sender_addr, receiver_addr):
    # start receiving data from the socket
    with open(f"./{receiver_addr}/recv/logs.txt", "a") as f:
        while True:
            received = client.recv(BUFFER_SIZE).decode()
            data_info = received.split(SEPARATOR)
            # recv message
            if data_info[0] == MESSAGE_TAG:
                # print("Message: " + data_info[1])
                f.write(f"New message from {sender_addr}: " + data_info[1] + "\n")
                f.flush()
            # recv file
            elif data_info[0] == FILE_TAG:
                f.write(f"New file from {sender_addr}: " + data_info[1])
                f.flush()
                filename = f"./{receiver_addr}/recv/files/{os.path.basename(data_info[1])}"
                filesize = int(data_info[2])
                recv_file(filename, filesize, client)

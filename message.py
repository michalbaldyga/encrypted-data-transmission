import pickle
import socket
import os
from constants import *
from crypto import encrypt, decrypt


def recv_file(filename: str, filesize: int, conn: socket.socket, private_key):
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


def send_file(filename: str, filesize: int, conn: socket.socket, recvied_public_key):
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


def send(client: socket.socket, session_key):
    while True:
        option = input("1.Send message\n2.Send file\n3.Exit\nChoose option: ")

        # send message
        if option == "1":
            mode = input("Mode (CBC, ECB): ")
            message = input("Message: ")
            encrypted_message, params = encrypt(message.encode(), mode, session_key)
            data = {
                MESSAGE_TAG: encrypted_message,
                PARAMETERS_TAG: params
            }
            serialized_data = pickle.dumps(data)
            client.sendall(serialized_data)  # -> bytes
        # send file
        elif option == "2":
            # send the filename and filesize
            filename = input("Filename: ")
            filesize = os.path.getsize(filename)
            client.send(f"{FILE_TAG}{SEPARATOR}{filename}{SEPARATOR}{filesize}".encode())
            send_file(filename, filesize, client, session_key)

        # exit
        else:
            client.close()
            break


def recv(client: socket.socket, sender_addr, receiver_addr, session_key):
    # start receiving data from the socket
    with open(f"./{receiver_addr}/recv/logs.txt", "a") as f:
        # params_not_set = True
        while True:
            '''
            # if the params are not set you can not decode the message
            while params_not_set:
                received = client.recv(BUFFER_SIZE)
                try:
                    params = pickle.loads(received)
                    params_not_set = False
                except pickle.UnpicklingError as e:
                    continue
            '''
            received = client.recv(BUFFER_SIZE)
            # data = dict ( TAG : encrypted_data, PARAM_TAG : dict(param)}
            data = pickle.loads(received)
            splited_data = list(data.items())
            # recv message
            if splited_data[CONTENT][TAG] == MESSAGE_TAG:
                message = decrypt(splited_data[CONTENT][DATA],
                                  session_key,
                                  splited_data[PARAMS][TYPE]['MODE'],
                                  splited_data[PARAMS][TYPE]['IV'])
                f.write(f"New message from {sender_addr}: " + message + "\n")
                f.flush()
            # recv file
            elif splited_data[CONTENT][TAG] == FILE_TAG:

                f.write(f"New file from {sender_addr}: " + splited_data[CONTENT][DATA])
                f.flush()
                filename = f"./{receiver_addr}/recv/files/{os.path.basename(list(data)[1])}"
                # filesize = int(data_info[2])
                # recv_file(filename, filesize, client, session_key)

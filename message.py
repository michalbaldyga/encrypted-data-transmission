import pickle
import socket
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms

from constants import *
from crypto import encrypt, decrypt, encrypt_params, decrypt_params


def recv_file(filename: str, filesize: int, conn: socket.socket, params):
    """receiving the file from the socket and writing to the file stream"""
    with open(filename, "wb") as f:
        while True:
            bytes_read = conn.recv(BUFFER_SIZE)
            if bytes_read.endswith(END_TAG.encode()):
                # file transmitting is done
                bytearray_obj = bytearray(bytes_read)
                bytearray_obj = bytearray_obj[:-len(END_TAG)]
                modified_bytes = bytes(bytearray_obj)
                decrypted_data = decrypt(modified_bytes, params)
                f.write(decrypted_data)
                f.flush()
                break
            else:
                decrypted_data = decrypt(bytes_read, params)
                f.write(decrypted_data)


def send_file(filename: str, filesize: int, conn: socket.socket, params):
    """sending the file"""
    with open(filename, "rb") as f:
        while True:
            # read the bytes from the file
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                # file transmitting is done
                break

            encrypted_data = encrypt(bytes_read, params)
            conn.sendall(encrypted_data)
        conn.send("<END>".encode())


def send(client: socket.socket, session_key):
    while True:
        option = input("1.Send message\n2.Send file\n3.Exit\nChoose option: ")
        mode = ""
        params = {"MODE": mode,
                  "IV": os.urandom(16),
                  "PADDER": padding.PKCS7(128),
                  "ALGORITHM": algorithms.AES(session_key)}
        # send message
        if option == "1":
            mode = input("Mode (CBC, ECB): ")
            params["MODE"] = mode
            message = input("Message: ")
            encrypted_message = encrypt(message.encode(), params)
            data = {
                MESSAGE_TAG: encrypted_message,
                PARAMETERS_TAG: encrypt_params(params, session_key)
            }
            serialized_data = pickle.dumps(data)
            client.sendall(serialized_data)  # -> bytes
        # send file
        elif option == "2":
            mode = input("Mode (CBC, ECB): ")
            params["MODE"] = mode
            # send the filename and filesize
            filename = input("Filename: ")
            filesize = os.path.getsize(filename)
            data = {
                FILENAME_TAG: filename,
                SIZE_TAG: filesize,
                PARAMETERS_TAG: encrypt_params(params, session_key)
            }
            serialized_data = pickle.dumps(data)
            client.send(serialized_data)
            send_file(filename, filesize, client, params)
        # exit
        else:
            client.close()
            break


def recv(client: socket.socket, sender_addr, receiver_addr, session_key):
    # start receiving data from the socket
    with open(f"./{receiver_addr}/recv/logs.txt", "a") as f:
        # params_not_set = True
        while True:
            received = client.recv(BUFFER_SIZE)
            # data = dict ( TAG : encrypted_data, PARAM_TAG : dict(param)}
            data = pickle.loads(received)
            splited_data = list(data.items())
            # recv message
            if splited_data[CONTENT][TAG] == MESSAGE_TAG:
                message = decrypt(splited_data[CONTENT][DATA],
                                  decrypt_params(splited_data[PARAMS][TYPE], session_key))
                f.write(f"New message from {sender_addr}: " + message.decode() + "\n")
                f.flush()
            # recv file
            elif splited_data[CONTENT][TAG] == FILENAME_TAG:
                f.write(f"New file from {sender_addr}: " + splited_data[CONTENT][DATA])
                f.flush()
                filename = f"./{receiver_addr}/recv/files/{os.path.basename(splited_data[CONTENT][DATA])}"
                filesize = int(splited_data[SIZE][DATA])
                recv_file(filename, filesize, client, decrypt_params(splited_data[PARAMS2][TYPE], session_key))

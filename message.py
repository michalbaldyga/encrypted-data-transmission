import pickle
import socket
import os

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import algorithms

from constants import *
from crypto import encrypt, decrypt, encrypt_params, decrypt_params


def recv_file(filename: str, filesize: int, conn: socket.socket, params):
    """Receiving the file from the socket and writing to the file stream"""
    with open(filename, "wb") as f:
        while True:
            bytes_read = conn.recv(BUFFER_SIZE)
            if bytes_read.endswith(END_TAG.encode()):
                # Remove the END_TAG before decrypting
                bytearray_obj = bytearray(bytes_read)
                bytearray_obj = bytearray_obj[:-len(END_TAG)]
                modified_bytes = bytes(bytearray_obj)

                # Decrypt received bytes and save it
                decrypted_data = decrypt(modified_bytes, params)
                f.write(decrypted_data)
                f.flush()
                break
            else:
                # Decrypt received bytes and save it
                decrypted_data = decrypt(bytes_read, params)
                f.write(decrypted_data)


def send_file(filename: str, filesize: int, conn: socket.socket, params):
    """Sending the file"""
    with open(filename, "rb") as f:
        while True:
            # Read the bytes from the file
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                # File transmitting is done
                break
            # Encryption of bytes and their transmission
            encrypted_data = encrypt(bytes_read, params)
            conn.sendall(encrypted_data)
        conn.send("<END>".encode())


def send(client: socket.socket, session_key):
    while True:
        option = input("1.Send message\n2.Send file\n3.Exit\nChoose option: ")
        mode = ""
        # Create a dictionary with the parameters for encrypt/decrypt
        params = {"MODE": mode,
                  "IV": os.urandom(16),
                  "PADDER": padding.PKCS7(128),
                  "ALGORITHM": algorithms.AES(session_key)}

        # Send message
        if option == "1":
            mode = input("Mode (CBC, ECB): ")
            params["MODE"] = mode
            message = input("Message: ")
            encrypted_message = encrypt(message.encode(), params)
            # Create a dictionary with encrypted message and encrypted parameters
            data = {
                MESSAGE_TAG: encrypted_message,
                PARAMETERS_TAG: encrypt_params(params, session_key)
            }
            serialized_data = pickle.dumps(data)
            client.sendall(serialized_data)  # -> bytes
            print("[+] Encrypted message sent.")

        # Send file
        elif option == "2":
            mode = input("Mode (CBC, ECB): ")
            params["MODE"] = mode
            # Send the filename and filesize
            filename = input("Filename: ")
            filesize = os.path.getsize(filename)
            # Creating a dictionary with filename, filesize and encrypted parameters
            data = {
                FILENAME_TAG: filename,
                SIZE_TAG: filesize,
                PARAMETERS_TAG: encrypt_params(params, session_key)
            }
            serialized_data = pickle.dumps(data)
            # First sending serialized dictionary with file info and params
            client.send(serialized_data)
            # Sending the content of the file
            send_file(filename, filesize, client, params)
            print("[+] Encrypted file sent.")

        # Exit
        else:
            client.close()
            break


def recv(client: socket.socket, sender_addr, receiver_addr, session_key):
    # Start receiving data from the socket
    with open(f"./{receiver_addr}/recv/logs.txt", "a") as f:
        # params_not_set = True
        while True:
            received = client.recv(BUFFER_SIZE)
            # data = dict ( TAG : encrypted_data, PARAM_TAG : dict(param)}
            data = pickle.loads(received)
            splited_data = list(data.items())

            # Recv message
            if splited_data[CONTENT][TAG] == MESSAGE_TAG:
                message = decrypt(splited_data[CONTENT][DATA],
                                  decrypt_params(splited_data[PARAMS][TYPE], session_key))
                f.write(f"New message from {sender_addr}: " + message.decode() + "\n")
                f.flush()
                print("\n[+] New message received.")

            # Recv file
            elif splited_data[CONTENT][TAG] == FILENAME_TAG:
                f.write(f"New file from {sender_addr}: " + splited_data[CONTENT][DATA])
                f.flush()
                filename = f"./{receiver_addr}/recv/files/{os.path.basename(splited_data[CONTENT][DATA])}"
                filesize = int(splited_data[SIZE][DATA])
                recv_file(filename, filesize, client, decrypt_params(splited_data[PARAMS2][TYPE], session_key))
                print("\n[+] New file received.")

import socket
from constants import BUFFER_SIZE, END_TAG


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

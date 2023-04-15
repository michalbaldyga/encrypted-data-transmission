import socket


def sending_messages(client: socket.socket):
    while True:
        message = input("")
        client.send(message.encode())
        print("You: " + message)


def receiving_messages(client: socket.socket):
    while True:
        print("Partner: " + client.recv(1024).decode())

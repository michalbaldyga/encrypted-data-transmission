import socket
import threading
from message import sending_messages, receiving_messages
from constants import *

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
client, _ = server.accept()

threading.Thread(target=sending_messages, args=(client, )).start()
threading.Thread(target=receiving_messages, args=(client, )).start()

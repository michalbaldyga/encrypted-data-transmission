import socket
import threading
from message import sending_messages, receiving_messages
from constants import *

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

threading.Thread(target=sending_messages, args=(client, )).start()
threading.Thread(target=receiving_messages, args=(client, )).start()

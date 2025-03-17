import socket
import threading

#######################################################
#                                                     #
#   Simple echo server                                #
#   python(3) echo.py                                 #
#                                                     #
#######################################################

TIMEOUT = 120 # seconds
PORT = 7


def handle(client_socket):
    while True:
        try:
            data = client_socket.recv(4096)
        except TimeoutError:
            return
        client_socket.send(data)

# creating server socket
server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("0.0.0.0", PORT))

while True: # listen for incoming connections
    message, address = server.recvfrom(1024)
    #client_socket.settimeout(TIMEOUT)
    print(f"{PORT}: request from the ip {address[0]}")
    # spawn a new thread that run the function handle()
    server.sendto(message, address)
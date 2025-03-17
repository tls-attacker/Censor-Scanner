import socket
import threading

TIMEOUT = 20000 # 10 seconds
ANSWER = b'AAAAA'
PORTS = 1
START_PORT = 53

def handle(client_socket, address):
    with client_socket:
        sent = False
        while True:
            data = client_socket.recv(4096)
            if not sent:
                client_socket.send(ANSWER)
                sent = True
            if not data:
                break

def server_port(port: int):
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0",port))

        while True: # listen for incoming connections
            message, address = server.recvfrom(4096)
            #client_socket.settimeout(TIMEOUT)
            print(f"{port}: request from the ip {address[0]}")
            # spawn a new thread that run the function handle()
            server.sendto(ANSWER, address)
    except Exception as e:
        print(f"{port}: {e}") 

# opening PORTS many server ports
threads = []
for port in range(START_PORT,START_PORT+PORTS):
    threads += [threading.Thread(target=server_port, args=(port,))]
    print(port)
print(len(threads))
try:
    for thread in threads:
        thread.start()
except Exception as e:
    print(f"{thread}: {e}")

for thread in threads:
    thread.join()

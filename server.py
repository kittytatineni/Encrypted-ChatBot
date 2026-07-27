import socket
import threading

HOST = "127.0.0.1"
PORT = 5555

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = []
usernames = []


def broadcast(message):
    for client in clients:
        try:
            client.send(message)
        except:
            pass


def handle(client):
    while True:
        try:
            message = client.recv(1024)
            if not message:
                break
            broadcast(message)
        except:
            break

    if client in clients:
        index = clients.index(client)
        username = usernames[index]

        clients.remove(client)
        usernames.remove(username)

        client.close()

        print(f"{username} disconnected.")
        broadcast(f"SERVER: {username} left the chat.".encode())


def receive():
    print(f"Server running on {HOST}:{PORT}")

    while True:
        client, address = server.accept()

        print(f"Connection from {address}")

        client.send("USERNAME".encode())

        username = client.recv(1024).decode()

        usernames.append(username)
        clients.append(client)

        print(f"{username} joined.")

        broadcast(f"SERVER: {username} joined the chat.".encode())

        thread = threading.Thread(target=handle, args=(client,))
        thread.start()


receive()
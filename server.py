import socket
import threading
import struct

from cryptography.hazmat.primitives import serialization
from crypto import *

HOST = "127.0.0.1"
PORT = 5555

# One shared Fernet key for all chat clients
fernet_key = generate_key()
cipher = create_cipher(fernet_key)

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind((HOST, PORT))
server.listen()

clients = []
usernames = []
clients_lock = threading.Lock()


def send_frame(sock, data):
    """Send data with a 4-byte length header."""
    sock.sendall(struct.pack("!I", len(data)) + data)


def recv_exact(sock, size):
    """Receive exactly size bytes."""
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError("Connection closed.")

        data += chunk

    return data


def recv_frame(sock):
    """Receive length-prefixed data."""
    length = struct.unpack("!I", recv_exact(sock, 4))[0]
    return recv_exact(sock, length)


def broadcast(message):
    """Send an already-encrypted message to every connected client."""
    with clients_lock:
        current_clients = clients.copy()

    for client in current_clients:
        try:
            send_frame(client, message)
        except Exception:
            pass


def handle(client):
    while True:
        try:
            # Client messages are encrypted using the shared Fernet key.
            encrypted_message = recv_frame(client)
            broadcast(encrypted_message)

        except Exception:
            break

    with clients_lock:
        if client in clients:
            index = clients.index(client)
            username = usernames[index]

            clients.remove(client)
            usernames.remove(username)
        else:
            username = "Unknown user"

    client.close()

    print(f"{username} disconnected.")

    leave_message = encrypt(
        cipher,
        f"SERVER: {username} left the chat."
    )

    broadcast(leave_message)


def receive():
    print(f"Server running on {HOST}:{PORT}")

    while True:
        client, address = server.accept()
        print(f"Connection from {address}")

        try:
            # Receive the client's public RSA key
            client_public_key_data = recv_frame(client)

            client_public_key = serialization.load_pem_public_key(
                client_public_key_data
            )

            # Encrypt and send the shared Fernet key to this client
            encrypted_fernet_key = rsa_encrypt(
                client_public_key,
                fernet_key
            )

            send_frame(client, encrypted_fernet_key)

            # Ask for username
            send_frame(client, b"USERNAME")
            username = recv_frame(client).decode()

            with clients_lock:
                usernames.append(username)
                clients.append(client)

            print(f"{username} joined.")

            join_message = encrypt(
                cipher,
                f"SERVER: {username} joined the chat."
            )

            broadcast(join_message)

            thread = threading.Thread(
                target=handle,
                args=(client,),
                daemon=True
            )
            thread.start()

        except Exception as error:
            print(f"Failed to connect client: {error}")
            client.close()


receive()
import socket
import threading
import struct

from cryptography.hazmat.primitives import serialization
from crypto import *

HOST = "127.0.0.1"
PORT = 5555


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


# Create an RSA key pair for this client
private_key, public_key = generate_rsa_keys()

username = input("Enter username: ")

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Send this client's public RSA key to the server
client_public_key_data = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

send_frame(client, client_public_key_data)

# Receive the shared Fernet key, encrypted using this client's public RSA key
encrypted_fernet_key = recv_frame(client)
fernet_key = rsa_decrypt(private_key, encrypted_fernet_key)

cipher = create_cipher(fernet_key)

# Username handshake
request = recv_frame(client)

if request == b"USERNAME":
    send_frame(client, username.encode())


def receive():
    while True:
        try:
            encrypted_message = recv_frame(client)
            message = decrypt(cipher, encrypted_message)

            if isinstance(message, bytes):
                message = message.decode()

            print(message)

        except Exception:
            print("Disconnected from server.")
            client.close()
            break


def write():
    while True:
        try:
            message = input()
            full_message = f"{username}: {message}"

            encrypted_message = encrypt(cipher, full_message)
            send_frame(client, encrypted_message)

        except Exception:
            break


receive_thread = threading.Thread(target=receive, daemon=True)
receive_thread.start()

write_thread = threading.Thread(target=write, daemon=True)
write_thread.start()

write_thread.join()
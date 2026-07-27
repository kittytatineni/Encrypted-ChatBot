from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt(message):
    return cipher.encrypt(message.encode())

def decrypt(ciphertext):
    return cipher.decrypt(ciphertext).decode()
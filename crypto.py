from cryptography.fernet import Fernet

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


# ======================
# RSA
# ======================

def generate_rsa_keys():

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    return private_key, public_key



def rsa_encrypt(public_key, data):

    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )



def rsa_decrypt(private_key, encrypted):

    return private_key.decrypt(
        encrypted,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None
        )
    )



# ======================
# FERNET
# ======================


def generate_key():

    return Fernet.generate_key()



def create_cipher(key):

    return Fernet(key)



def encrypt(cipher, message):

    return cipher.encrypt(
        message.encode()
    )



def decrypt(cipher, encrypted):

    return cipher.decrypt(
        encrypted
    ).decode()
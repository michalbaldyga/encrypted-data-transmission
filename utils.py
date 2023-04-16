from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


# local key is just a password given by the user
# local key is used just for the PRIVATE KEY
# use it during creation of the client
def init_keys(client_id, local_key=None):
    # check if are the keys exist if not create them
    try:
        with open('keys/private_key/private_key_' + client_id + '.pem', 'rb') as private_key, \
                open('keys/public_key/public_key_' + client_id + '.pem', 'rb') as public_key:

            private_key = serialization.load_pem_private_key(
                private_key.read(),
                password=local_key.encode()
            )
            public_key = serialization.load_pem_public_key(
                public_key.read(),
            )

    except FileNotFoundError:
        # creation of the RSA keys to store on the hard disk
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Serialize (changing the format) to store RSA keys

        # private key -> password (local_key) needed
        pem_private_key = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(local_key.encode())
        )
        with open('private_key_' + client_id + '.pem', 'wb') as f:
            f.write(pem_private_key)

        # public key -> available for everyone (no password)
        pem_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open('public_key_' + client_id + '.pem', 'wb') as f:
            f.write(pem_public_key)

    return public_key, private_key

#def read_public_key(client_id):


# sended_data -> file/text/png
# mode -> CBC/ECB
def encrypt(data, _mode):
    # appends the bytes to make the sended_data the same size as block size (always 128 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    # 256 bits secret key known by a sender and receiver
    _session_key = os.urandom(32)
    _iv = None
    if _mode == 'CBC':
        # random 256 - bit iv
        _iv = os.urandom(32)
        cipher = Cipher(algorithms.AES256(session_key), modes.CBC(_iv))
    else:
        cipher = Cipher(algorithms.AES256(session_key), modes.ECB())

    encryptor = cipher.encryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    _ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    with open('encrypted_data/' + file_name, 'wb') as file:
        file.write(_ciphertext)

    # place for encryption a session_key by rsa public_key

    return _iv, _ciphertext, _session_key, _mode


def decrypt(_ciphertext, _session_key, _mode, _iv=None):
    if _mode == 'CBC':
        cipher = Cipher(algorithms.AES256(session_key), modes.CBC(_iv))
    else:
        cipher = Cipher(algorithms.AES256(session_key), modes.ECB())

    decryptor = cipher.decryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    data = decryptor.update(_ciphertext) + decryptor.finalize()

    # returning our block of sended_data without padding
    unpadder = padding.PKCS7(128).unpadder()
    byte_data = unpadder.update(data) + unpadder.finalize()

    with open('decrypted_data/' + file_name, 'wb') as file:
        file.write(byte_data)


# Press the green button in the gutter to run the script.
if __name__ == '__main__':

    for root, dirs, files in os.walk('sended_data'):
        for file_name in files:
            with open('sended_data/' + file_name, 'rb') as f:
                byte_file = f.read()
                # second arg pass by user
                iv, ciphertext, session_key, mode = encrypt(byte_file, "ECB")
                decrypt(ciphertext, session_key, mode, iv)

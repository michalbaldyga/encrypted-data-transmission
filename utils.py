from cryptography.hazmat.primitives import padding, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


# sended_data -> file/text/png
# mode -> CBC/ECB
def encrypt(data, _mode):
    # appends the bytes to make the sended_data the same size as block size (always 128 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    # 256 bits secret key known by a sender and receiver
    session_key = os.urandom(32)
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

    return _iv, _ciphertext, session_key, _mode


def decrypt(_ciphertext, session_key, _mode, _iv=None):
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
    # TODO ########################################################
    password = "Abcd123!"
    byte_password = bytes(password, encodings='utf-8')
    local_key = hashes.Hash(hashes.SHA256())
    local_key.update(byte_password)
    # creating a private RSA key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # BestAvailableEncryption is aes-256-cbc by default
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(local_key)
    )

    with open('private_key/private_key.pem', 'wb') as f:
        f.write(private_pem)

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open('public_key/public_key.pem', 'wb') as f:
        f.write(public_pem)
    ###############################################################

    for root, dirs, files in os.walk('sended_data'):
        for file_name in files:
            with open('sended_data/' + file_name, 'rb') as f:
                byte_file = f.read()
                # second arg pass by user
                iv, ciphertext, key, mode = encrypt(byte_file, "ECB")
                decrypt(ciphertext, key, mode, iv)

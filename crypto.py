from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import Cipher

from constants import PATH_TO_PRIVATE_KEY, PATH_TO_PUBLIC_KEY
import os


def encrypt_cipher_param(_mode, _iv, _used_algorithm, _key_size, _block_size):
    """
    _mode = _public_key.encrypt(
        _mode.decode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    _iv = _public_key.encrypt(
        _iv.decode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    """
    pass


# sended_data -> file/text/png
# mode -> CBC/ECB
def encrypt(data, _mode, _session_key):
    # appends the bytes to make the sended_data the same size as block size (always 128 bytes for AES)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()
    _iv = None
    if _mode == 'CBC':
        # random 256 - bit iv
        _iv = os.urandom(32)
        cipher = Cipher(algorithms.AES256(_session_key), modes.CBC(_iv))
    else:
        cipher = Cipher(algorithms.AES256(_session_key), modes.ECB())

    encryptor = cipher.encryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    _ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return _iv, _ciphertext, _session_key, _mode


def decrypt(_private_key, _ciphertext, _session_key, _mode, _iv=None):
    # decryption of the session key using private key
    _session_key = _private_key.decrypt(
        _session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    if _mode == 'CBC':
        cipher = Cipher(algorithms.AES256(_session_key), modes.CBC(_iv))
    else:
        cipher = Cipher(algorithms.AES256(_session_key), modes.ECB())

    decryptor = cipher.decryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    data = decryptor.update(_ciphertext) + decryptor.finalize()

    # returning our block of sended_data without padding
    unpadder = padding.PKCS7(128).unpadder()
    byte_data = unpadder.update(data) + unpadder.finalize()


def create_session_key(_public_key):
    # session key
    _session_key = os.urandom(32)
    _session_key = _public_key.encrypt(
        _session_key.decode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return _session_key


def hash_local_key(password: str) -> bytes:
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(password.encode())
    hash_password = hasher.finalize()
    return hash_password


def assign_rsa_keys(client_id, password):
    # RSA public and private keys
    try:
        _private_key, _public_key = load_rsa_keys(client_id + PATH_TO_PRIVATE_KEY,
                                                  client_id + PATH_TO_PUBLIC_KEY, password)
    except FileNotFoundError:
        _private_key, _public_key = create_rsa_keys()
        save_rsa_keys(_private_key, _public_key,
                      client_id + PATH_TO_PRIVATE_KEY,
                      client_id + PATH_TO_PUBLIC_KEY,
                      password)

    return _private_key, _public_key


def create_rsa_keys():
    _private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    _public_key = _private_key.public_key()

    return _private_key, _public_key


def save_rsa_keys(pr, pu, filename_pr, filename_pu, local_key):
    pem_pr = pr.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(local_key)
    )
    pem_pu = pu.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(filename_pr, 'wb') as pem_out_pr, open(filename_pu, 'wb') as pem_out_pu:
        pem_out_pr.write(pem_pr)
        pem_out_pu.write(pem_pu)


def load_rsa_keys(filename_pr, filename_pu, local_key):
    with open(filename_pr, 'rb') as pr, \
            open(filename_pu, 'rb') as pu:
        _private_key = serialization.load_pem_private_key(
            pr.read(),
            password=local_key,
            backend=default_backend()
        )
        _public_key = serialization.load_pem_public_key(
            pu.read(),
            backend=default_backend()
        )
    return _private_key, _public_key

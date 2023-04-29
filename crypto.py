import json

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import Cipher

from constants import PATH_TO_PRIVATE_KEY, PATH_TO_PUBLIC_KEY
import os


def encrypt_parameters(parameters):
    # Convert dictionary to JSON string
    json_string = json.dumps(parameters)

    # Generate a key for encryption
    key = Fernet.generate_key()

    # Create a Fernet object with the key
    f = Fernet(key)

    # Encrypt the JSON string
    encrypted_json_string = f.encrypt(json_string.encode())

    return encrypted_json_string


# sended_data -> file/text/png
# mode -> CBC/ECB
def encrypt(data, _mode, _session_key):
    # appends the bytes to make the sended_data the same size as block size (always 128 bytes for AES)
    block_size = 128
    padder = padding.PKCS7(block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    iv = None
    algorithm = algorithms.AES256(_session_key)
    if _mode == 'CBC':
        # random 256 - bit iv
        iv = os.urandom(32)
        mode = modes.CBC(iv)
        cipher = Cipher(algorithm, mode)
    else:
        mode = modes.ECB()
        cipher = Cipher(algorithm, mode)

    encryptor = cipher.encryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    _ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    # Encrypt parameters like : iv, mode, algorithm, key size, block size
    parameters = {
        "iv": iv,
        "mode": mode,
        "algorithm": algorithm,
        "key_size": 256,
        "block_size": block_size
    }
    encrypted_parameters = encrypt_parameters(parameters)
    return _ciphertext, encrypted_parameters


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
        private_key, public_key = load_rsa_keys(client_id + PATH_TO_PRIVATE_KEY,
                                                client_id + PATH_TO_PUBLIC_KEY, password)
    except FileNotFoundError:
        private_key, public_key = create_rsa_keys()
        save_rsa_keys(private_key, public_key,
                      client_id + PATH_TO_PRIVATE_KEY,
                      client_id + PATH_TO_PUBLIC_KEY,
                      password)

    return private_key, public_key


def create_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    return private_key, public_key


def save_rsa_keys(pr, pu, filename_pr, filename_pu, local_key):
    pem_pr = serialize_private_key(pr, local_key)
    pem_pu = serialize_public_key(pu)
    with open(filename_pr, 'wb') as pem_out_pr, open(filename_pu, 'wb') as pem_out_pu:
        pem_out_pr.write(pem_pr)
        pem_out_pu.write(pem_pu)


def load_rsa_keys(filename_pr, filename_pu, local_key):
    with open(filename_pr, 'rb') as pr, \
            open(filename_pu, 'rb') as pu:
        _private_key = deserialize_private_key(pr.read(), local_key)
        _public_key = deserialize_public_key(pu.read())
    return _private_key, _public_key


def serialize_public_key(public_key):
    public_key_serialized_ = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key_serialized_


def serialize_private_key(private_key, local_key):
    private_key_serialized_ = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(local_key)
    )
    return private_key_serialized_


def deserialize_private_key(serialized_private_key, local_key):
    _private_key = serialization.load_pem_private_key(
        serialized_private_key,
        password=local_key,
        backend=default_backend()
    )
    return _private_key


def deserialize_public_key(serialized_public_key):
    _public_key = serialization.load_pem_public_key(
        serialized_public_key,
        backend=default_backend()
    )
    return _public_key


def send_public_key(client, public_key):
    public_key_to_send = serialize_public_key(public_key)
    client.sendall(public_key_to_send)


def recv_public_key(client):
    serialized_public_key = client.recv(2048)
    deserialized_public_key = deserialize_public_key(serialized_public_key)
    return deserialized_public_key

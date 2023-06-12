import base64
import pickle

from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives.ciphers.base import Cipher

from constants import PATH_TO_PRIVATE_KEY, PATH_TO_PUBLIC_KEY
import os


def encrypt_params(params, session_key):
    encoded_key = base64.urlsafe_b64encode(session_key)
    cipher = Fernet(encoded_key)
    serialized_params = pickle.dumps(params)
    encrypted_params = cipher.encrypt(serialized_params)
    return encrypted_params


def decrypt_params(encrypted_params, session_key) -> dict:
    encoded_key = base64.urlsafe_b64encode(session_key)
    cipher = Fernet(encoded_key)
    decrypted_params = cipher.decrypt(encrypted_params)
    deserialized_params = pickle.loads(decrypted_params)
    return deserialized_params


# sended_data -> file/text/png
# mode -> CBC/ECB
def encrypt(data, params):
    # appends the bytes to make the sended_data the same size as block size (always 128 bytes for AES)
    padder = params["PADDER"].padder()
    padded_data = padder.update(data) + padder.finalize()
    _iv = params["IV"]
    algorithm = params["ALGORITHM"]
    if params["MODE"] == "CBC":
        cipher = Cipher(algorithm, modes.CBC(_iv))
    else:
        cipher = Cipher(algorithm, modes.ECB())
    encryptor = cipher.encryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    _ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return _ciphertext


def decrypt(_ciphertext, params):
    algorithm = params["ALGORITHM"]
    _iv = params["IV"]
    if params["MODE"] == "CBC":
        cipher = Cipher(algorithm, modes.CBC(_iv))
    else:
        cipher = Cipher(algorithm, modes.ECB())
    decryptor = cipher.decryptor()
    # Encrypt the plaintext and get the associated ciphertext.
    data = decryptor.update(_ciphertext) + decryptor.finalize()
    # returning our block of sended_data without padding
    unpadder = params["PADDER"].unpadder()
    bytes_message = unpadder.update(data) + unpadder.finalize()  # -> bytes
    return bytes_message


# -------------- SESSION KEY ---------------------------------------------
def create_session_key():
    session_key = os.urandom(32)  # -> bytes
    return session_key


def encrypt_session_key(receiver_public_key, session_key) -> bytes:
    encrypted_session_key = receiver_public_key.encrypt(
        session_key,  # -> bytes
        asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_session_key


def decrypt_session_key(private_key, encrypted_session_key):
    # decryption of the session key using private key
    _session_key = private_key.decrypt(
        encrypted_session_key,
        asy_padding.OAEP(
            mgf=asy_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return _session_key


def send_session_key(client, receiver_public_key, session_key):
    encrypted_session_key = encrypt_session_key(receiver_public_key, session_key)
    client.sendall(encrypted_session_key)


def recv_session_key(client, private_key):
    encrypted_session_key = client.recv(2048)
    session_key = decrypt_session_key(private_key, encrypted_session_key)
    return session_key


# ------- RSA KEYS --------------------------------------------
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


# ------------- PRIVATE / PUBLIC KEYS ------------------------
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


def serialize_public_key(public_key):
    public_key_serialized_ = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return public_key_serialized_


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

import os
from cryptography.hazmat.primitives import hashes


def login(client_id: int) -> bytes:
    # registration/login
    pass_file = str(client_id) + "/keys/local_key/local_key.txt"
    file = open(pass_file, "r+b")
    hash_password = None

    # if there is no password, we add one
    if os.path.getsize(pass_file) == 0:
        password = input("Password: ")
        hash_password = hash_local_key(password)
        file.write(hash_password)
    # if there is already password
    else:
        password_to_check = file.read()
        while True:
            password = input("Password: ")
            hash_password = hash_local_key(password)
            if hash_password == password_to_check:
                break
    return hash_password


def hash_local_key(password: str) -> bytes:
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash)
    hasher.update(password.encode())
    hash_password = hasher.finalize()
    return hash_password

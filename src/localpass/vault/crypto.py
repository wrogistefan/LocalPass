import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

# Argon2id parameter profile for vault key derivation.
# Keeping these as constants allows future tuning while preserving
# format compatibility for existing vaults.
ARGON2ID_LENGTH = 32
ARGON2ID_ITERATIONS = 2
ARGON2ID_MEMORY_COST = 102_400  # in kibibytes
ARGON2ID_LANES = 8


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=ARGON2ID_LENGTH,
        iterations=ARGON2ID_ITERATIONS,
        memory_cost=ARGON2ID_MEMORY_COST,
        lanes=ARGON2ID_LANES,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

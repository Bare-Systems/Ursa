#!/usr/bin/env python3
"""
Ursa Major — Crypto Layer
==========================
AES-256-GCM encryption for C2 communications.
Each session gets a unique key negotiated at registration.
"""

import base64
import hashlib
import json
import os
import string

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CRYPTO_SUITE = "AES-256-GCM"
CRYPTO_FRAME_VERSION = 2
FRAME_MAGIC = b"URS2"
NONCE_SIZE = 12
TAG_SIZE = 16
AAD = b"ursa-major-c2:v2:aes-256-gcm"


class UrsaCrypto:
    """Versioned AES-256-GCM encryption for C2 payload envelopes.

    Message format:
        [4 bytes: magic/version][12 bytes: nonce][N bytes: ciphertext + 16-byte tag]

    Legacy SHA-derived CTR/HMAC frames are intentionally rejected so pre-AEAD
    encrypted sessions fail closed and must re-register with an updated implant.
    """

    def __init__(self, key: bytes | str):
        self.key = self._normalize_key(key)
        self._aead = AESGCM(self.key)

    @staticmethod
    def _normalize_key(key: bytes | str) -> bytes:
        """Return a 32-byte AES key from a session key or shared secret."""
        if isinstance(key, str):
            candidate = key.strip()
            if (
                len(candidate) == 64
                and all(ch in string.hexdigits for ch in candidate)
            ):
                return bytes.fromhex(candidate)
            key = candidate.encode()

        if len(key) == 32:
            return key
        return hashlib.sha256(key + b":aead").digest()

    def encrypt(self, plaintext: bytes | str, nonce: bytes | None = None) -> bytes:
        """Encrypt data with AES-256-GCM and return a versioned frame."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode()

        if nonce is None:
            nonce = os.urandom(NONCE_SIZE)
        if len(nonce) != NONCE_SIZE:
            raise ValueError(f"AES-GCM nonce must be {NONCE_SIZE} bytes")

        ciphertext = self._aead.encrypt(nonce, plaintext, AAD)
        return FRAME_MAGIC + nonce + ciphertext

    def decrypt(self, data: bytes) -> bytes:
        """Decrypt data encrypted with encrypt().

        Verifies AES-GCM authentication before returning plaintext.
        """
        minimum_size = len(FRAME_MAGIC) + NONCE_SIZE + TAG_SIZE
        if len(data) < minimum_size:
            raise ValueError("Data too short")

        if not data.startswith(FRAME_MAGIC):
            raise ValueError("Unsupported legacy crypto frame; re-register session")

        nonce_start = len(FRAME_MAGIC)
        nonce_end = nonce_start + NONCE_SIZE
        nonce = data[nonce_start:nonce_end]
        ciphertext = data[nonce_end:]
        try:
            return self._aead.decrypt(nonce, ciphertext, AAD)
        except InvalidTag as exc:
            raise ValueError("AES-GCM authentication failed") from exc

    def encrypt_json(self, obj) -> str:
        """Encrypt a JSON-serializable object, return base64 string."""
        plaintext = json.dumps(obj).encode()
        encrypted = self.encrypt(plaintext)
        return base64.b64encode(encrypted).decode()

    def decrypt_json(self, data: str):
        """Decrypt a base64 string back to a Python object."""
        encrypted = base64.b64decode(data)
        plaintext = self.decrypt(encrypted)
        return json.loads(plaintext.decode())


def generate_session_key() -> str:
    """Generate a random 32-byte session key as hex string."""
    return os.urandom(32).hex()


def derive_key(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    """Derive an encryption key from a password using PBKDF2.

    Returns (key, salt) tuple.
    """
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return key, salt

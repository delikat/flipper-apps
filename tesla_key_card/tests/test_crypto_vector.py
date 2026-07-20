#!/usr/bin/env python3
"""Verify the fixed-width ECDH/SHA-1/AES construction used by Gauss."""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


card_private = ec.derive_private_key(1, ec.SECP256R1())
vehicle_private = ec.derive_private_key(2, ec.SECP256R1())
shared_x = card_private.exchange(ec.ECDH(), vehicle_private.public_key())

assert shared_x.hex() == "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978"

digest = hashes.Hash(hashes.SHA1())
digest.update(shared_x)
aes_key = digest.finalize()[:16]
assert aes_key.hex() == "b59d61fedc3b7a1ee22fde1780a59522"

plaintext = bytes.fromhex("deadbeef445566778899aabbccddeeff")
encryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
response = encryptor.update(plaintext) + encryptor.finalize()
assert response.hex() == "437cc3cd96d48827152e34004f6295ca"

print("Crypto vector passed")

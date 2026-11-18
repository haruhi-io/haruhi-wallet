"""Ed25519 keypairs (RFC 8032) via the `cryptography` package."""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


@dataclass(frozen=True)
class Keypair:
    private_key_hex: str  # 32-byte Ed25519 private key (seed)
    public_key_hex: str  # 32-byte Ed25519 public key

    @property
    def private_key(self) -> bytes:
        return bytes.fromhex(self.private_key_hex)

    @property
    def public_key(self) -> bytes:
        return bytes.fromhex(self.public_key_hex)


def generate_keypair(seed: bytes | None = None) -> Keypair:
    """Keypair from a 32-byte private key, or a fresh random one.

    A seed that is not 32 bytes is hashed to 32 with SHA-256 first.
    """
    raw = seed if seed is not None else secrets.token_bytes(32)
    if len(raw) != 32:
        raw = hashlib.sha256(raw).digest()
    sk = Ed25519PrivateKey.from_private_bytes(raw)
    pub = sk.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Keypair(private_key_hex=raw.hex(), public_key_hex=pub.hex())


def sign_message(keypair: Keypair, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(keypair.private_key).sign(message)


def verify_message(public_key_hex: str, message: bytes, signature: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex)).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False

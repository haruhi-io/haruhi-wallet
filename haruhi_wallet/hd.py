"""SLIP-0010 key derivation for Ed25519 (the Ed25519 version of BIP-32).

Ed25519 only supports hardened derivation, so every path step is hardened.
Haruhi accounts use the BIP-44 layout m/44'/<coin_type>'/<account>'
(one key per account, as Stellar does), with coin_type from haruhi_wallet.network:
1031 on mainnet, 1 on testnet and regtest.
"""

from __future__ import annotations

import hashlib
import hmac

from haruhi_wallet.keys import Keypair, generate_keypair

HARDENED = 0x80000000
_CURVE_KEY = b"ed25519 seed"


def master_key(seed: bytes) -> tuple[bytes, bytes]:
    """(private key, chain code) for path m."""
    i = hmac.new(_CURVE_KEY, seed, hashlib.sha512).digest()
    return i[:32], i[32:]


def child_key(key: bytes, chain_code: bytes, index: int) -> tuple[bytes, bytes]:
    if index < HARDENED:
        raise ValueError("Ed25519 (SLIP-0010) supports hardened derivation only")
    data = b"\x00" + key + index.to_bytes(4, "big")
    i = hmac.new(chain_code, data, hashlib.sha512).digest()
    return i[:32], i[32:]


def parse_path(path: str) -> list[int]:
    parts = path.strip().split("/")
    if parts[0] != "m":
        raise ValueError(f"path must start with m: {path!r}")
    out = []
    for p in parts[1:]:
        if not p.endswith(("'", "h", "H")):
            raise ValueError(f"every step must be hardened (add '): {path!r}")
        n = int(p[:-1])
        if not 0 <= n < HARDENED:
            raise ValueError(f"path index out of range: {p}")
        out.append(n + HARDENED)
    return out


def derive_private_key(seed: bytes, path: str) -> bytes:
    key, chain = master_key(seed)
    for index in parse_path(path):
        key, chain = child_key(key, chain, index)
    return key


def account_path(coin_type: int, account: int) -> str:
    return f"m/44'/{coin_type}'/{account}'"


def derive_keypair(seed: bytes, path: str) -> Keypair:
    return generate_keypair(derive_private_key(seed, path))

"""Haruhi addresses: bech32 (prefix `haruhi` on mainnet, `testhrh` on testnet) + 20-byte pubkey hash."""

from __future__ import annotations

import hashlib

from haruhi_wallet import network
from haruhi_wallet.bech32 import decode_segwit_style, encode_segwit_style
from haruhi_wallet.keys import Keypair, generate_keypair as _gen_kp

WITNESS_VERSION = 0


def hrp() -> str:
    """Address prefix for the current NETWORK (see haruhi_wallet/network.py)."""
    return network.current().hrp


class AddressError(ValueError):
    pass


def pubkey_hash(public_key: bytes) -> bytes:
    return hashlib.sha256(public_key).digest()[:20]


def pubkey_to_address(public_key_hex: str) -> str:
    prog = pubkey_hash(bytes.fromhex(public_key_hex))
    addr = encode_segwit_style(hrp(), WITNESS_VERSION, prog)
    if addr is None:
        raise AddressError("failed to encode address")
    return addr


def is_valid_address(address: str) -> bool:
    decoded = decode_segwit_style(hrp(), address)
    return decoded is not None and decoded[0] == WITNESS_VERSION and len(decoded[1]) == 20


def address_payload(address: str) -> bytes:
    decoded = decode_segwit_style(hrp(), address)
    if decoded is None or decoded[0] != WITNESS_VERSION:
        raise AddressError(f"invalid haruhi address: {address}")
    return decoded[1]


def generate_keypair() -> tuple[Keypair, str]:
    kp = _gen_kp()
    return kp, pubkey_to_address(kp.public_key_hex)
"""Minimal Bech32 (BIP-0173) for Haruhi addresses — no BTC dependency."""

from __future__ import annotations

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> list[int] | None:
    acc = 0
    bits = 0
    ret: list[int] = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def bech32_encode(hrp: str, data: list[int]) -> str:
    combined = data + [0, 0, 0, 0, 0, 0]
    polymod = _polymod(_hrp_expand(hrp) + combined) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in data + checksum)


def bech32_decode(addr: str) -> tuple[str, list[int]] | tuple[None, None]:
    if any(ord(x) < 33 or ord(x) > 126 for x in addr):
        return None, None
    if addr.lower() != addr and addr.upper() != addr:
        return None, None
    addr = addr.lower()
    pos = addr.rfind("1")
    if pos < 1 or pos + 7 > len(addr) or len(addr) > 90:
        return None, None
    if not all(c in CHARSET for c in addr[pos + 1 :]):
        return None, None
    hrp = addr[:pos]
    data = [CHARSET.find(c) for c in addr[pos + 1 :]]
    if _polymod(_hrp_expand(hrp) + data) != 1:
        return None, None
    return hrp, data[:-6]


def encode_segwit_style(hrp: str, witver: int, witprog: bytes) -> str | None:
    if witver > 16 or not (2 <= len(witprog) <= 40):
        return None
    data = [witver] + (_convertbits(witprog, 8, 5) or [])
    return bech32_encode(hrp, data)


def decode_segwit_style(hrp_expected: str, addr: str) -> tuple[int, bytes] | None:
    hrp, data = bech32_decode(addr)
    if hrp is None or data is None or hrp != hrp_expected or not data:
        return None
    witver = data[0]
    decoded = _convertbits(bytes(data[1:]), 5, 8, False)
    if decoded is None or not (2 <= len(decoded) <= 40):
        return None
    return witver, bytes(decoded)
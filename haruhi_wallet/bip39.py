"""BIP-39 seed phrases (English word list), standard library only.

The word list is the official one from bitcoin/bips (bip-0039/english.txt),
sha256 2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda.
"""

from __future__ import annotations

import hashlib
import secrets
import unicodedata
from functools import lru_cache
from pathlib import Path

WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
_WORDLIST_PATH = Path(__file__).with_name("bip39_english.txt")


class MnemonicError(ValueError):
    pass


@lru_cache(maxsize=1)
def wordlist() -> tuple[str, ...]:
    raw = _WORDLIST_PATH.read_bytes()
    if hashlib.sha256(raw).hexdigest() != WORDLIST_SHA256:
        raise RuntimeError(f"{_WORDLIST_PATH.name} does not match the official BIP-39 list")
    words = tuple(raw.decode("utf-8").split())
    assert len(words) == 2048
    return words


def entropy_to_mnemonic(entropy: bytes) -> str:
    if len(entropy) not in (16, 20, 24, 28, 32):
        raise MnemonicError("entropy must be 16, 20, 24, 28 or 32 bytes")
    checksum_bits = len(entropy) * 8 // 32
    checksum = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    n = (int.from_bytes(entropy, "big") << checksum_bits) | checksum
    total_words = (len(entropy) * 8 + checksum_bits) // 11
    words = wordlist()
    return " ".join(words[(n >> (11 * (total_words - 1 - i))) & 0x7FF] for i in range(total_words))


def generate_mnemonic(words: int = 24) -> str:
    sizes = {12: 16, 15: 20, 18: 24, 21: 28, 24: 32}
    if words not in sizes:
        raise MnemonicError("words must be 12, 15, 18, 21 or 24")
    return entropy_to_mnemonic(secrets.token_bytes(sizes[words]))


def normalize(mnemonic: str) -> str:
    return " ".join(unicodedata.normalize("NFKD", mnemonic).lower().split())


def mnemonic_to_entropy(mnemonic: str) -> bytes:
    """Decode and check a phrase. Raises MnemonicError on a typo or bad checksum."""
    parts = normalize(mnemonic).split(" ")
    if len(parts) not in (12, 15, 18, 21, 24):
        raise MnemonicError("a seed phrase has 12, 15, 18, 21 or 24 words")
    index = {w: i for i, w in enumerate(wordlist())}
    n = 0
    for w in parts:
        if w not in index:
            raise MnemonicError(f"not a BIP-39 word: {w!r}")
        n = (n << 11) | index[w]
    checksum_bits = len(parts) * 11 // 33
    entropy_bits = len(parts) * 11 - checksum_bits
    entropy = (n >> checksum_bits).to_bytes(entropy_bits // 8, "big")
    expected = hashlib.sha256(entropy).digest()[0] >> (8 - checksum_bits)
    if n & ((1 << checksum_bits) - 1) != expected:
        raise MnemonicError("seed phrase checksum does not match (a word is wrong or out of order)")
    return entropy


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """64-byte seed. Checks the phrase first."""
    mnemonic_to_entropy(mnemonic)
    m = normalize(mnemonic).encode("utf-8")
    salt = ("mnemonic" + unicodedata.normalize("NFKD", passphrase)).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", m, salt, 2048)

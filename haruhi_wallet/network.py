"""Which Haruhi network this process is on: address prefix and BIP-44 coin type.

Set NETWORK=mainnet | testnet | regtest (default regtest, same as chain.node).
Every process that checks addresses (node, wallet, tools) must agree. testnet and regtest share the `testhrh` prefix and the standard
testnet coin type 1, so a dev or test wallet can never make a mainnet address.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Network:
    name: str
    hrp: str  # bech32 human-readable part (SLIP-0173)
    coin_type: int  # BIP-44 coin type (SLIP-0044); 1 = every testnet


MAINNET = Network("mainnet", "haruhi", 1031)
TESTNET = Network("testnet", "testhrh", 1)
REGTEST = Network("regtest", "testhrh", 1)

NETWORKS = {n.name: n for n in (MAINNET, TESTNET, REGTEST)}

# Every prefix any Haruhi network uses, for "does this look like one of our
# addresses at all?" checks. A wrong-network address must be rejected, not
# waved through as "not an address".
ALL_PREFIXES = tuple(sorted({n.hrp + "1" for n in NETWORKS.values()}))


def current() -> Network:
    """Read NETWORK on every call so tests and tools can switch it."""
    name = os.getenv("NETWORK", "regtest").strip().lower()
    try:
        return NETWORKS[name]
    except KeyError:
        raise ValueError(f"unknown NETWORK {name!r}; use one of {sorted(NETWORKS)}") from None


def looks_like_address(s: str) -> bool:
    """True if `s` starts with any Haruhi network's prefix (valid or not)."""
    return s.lower().startswith(ALL_PREFIXES)

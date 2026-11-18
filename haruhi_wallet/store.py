"""Local wallet file store. Protect this file: it holds the seed phrase and private keys.

Wallet file version 2 holds a BIP-39 seed phrase. Accounts are derived from it
with SLIP-0010 at m/44'/<coin_type>'/<account>' (see haruhi_wallet/hd.py), so the
24 words alone restore every derived account. Keys imported with
`import_keypair`, and accounts from version-1 files (random keys, no seed),
are kept as "imported": the seed phrase does NOT restore those.

A wallet belongs to one network (haruhi_wallet/network.py). Opening it with a
different NETWORK is refused, so testnet keys never end up making mainnet
addresses or the other way round.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from haruhi_wallet import bip39, hd, network
from haruhi_wallet.address import is_valid_address, pubkey_to_address
from haruhi_wallet.keys import Keypair

FILE_VERSION = 2


class WalletError(ValueError):
    pass


@dataclass
class WalletAccount:
    label: str
    address: str
    public_key_hex: str
    private_key_hex: str
    created_at: float
    path: str = ""  # derivation path; "" = imported key (not restorable from the seed)


class WalletStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.accounts: list[WalletAccount] = []
        self.mnemonic: str | None = None
        self.network = network.current()
        self._load()

    # ------------------------------------------------------------ file

    def _load(self) -> None:
        if not self.path.exists():
            return
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        saved_net = raw.get("network")
        if saved_net is not None and saved_net != self.network.name:
            # testnet and regtest share keys and prefix, so treat them as one.
            if network.NETWORKS.get(saved_net, self.network).hrp != self.network.hrp:
                raise WalletError(
                    f"{self.path} is a {saved_net} wallet but NETWORK={self.network.name}; "
                    f"set NETWORK={saved_net} or use another wallet file"
                )
        self.mnemonic = raw.get("mnemonic")
        self.accounts = [WalletAccount(**a) for a in raw.get("accounts", [])]

    def save(self) -> None:
        payload = {
            "coin": "haruhi",
            "version": FILE_VERSION,
            "network": self.network.name,
            "warning": "Seed phrase and private keys in plaintext. Anyone with this file can spend the coins.",
            "mnemonic": self.mnemonic,
            "accounts": [asdict(a) for a in self.accounts],
        }
        self.path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    # ------------------------------------------------------------ seed

    def has_seed(self) -> bool:
        return bool(self.mnemonic)

    def init_seed(self, mnemonic: str | None = None, words: int = 24) -> str:
        """Give the wallet a seed phrase (new, or restored from `mnemonic`). Returns it."""
        if self.mnemonic:
            raise WalletError("wallet already has a seed phrase")
        if mnemonic is None:
            mnemonic = bip39.generate_mnemonic(words)
        else:
            bip39.mnemonic_to_entropy(mnemonic)  # raises on a typo or bad checksum
            mnemonic = bip39.normalize(mnemonic)
        self.mnemonic = mnemonic
        self.save()
        return mnemonic

    def _seed(self) -> bytes:
        if not self.mnemonic:
            raise WalletError("wallet has no seed phrase")
        return bip39.mnemonic_to_seed(self.mnemonic)

    def _next_account_index(self) -> int:
        prefix = f"m/44'/{self.network.coin_type}'/"
        used = [int(a.path[len(prefix):].rstrip("'")) for a in self.accounts if a.path.startswith(prefix)]
        return max(used, default=-1) + 1

    # ------------------------------------------------------------ accounts

    def _add(self, label: str, keypair: Keypair, path: str) -> WalletAccount:
        if any(a.label == label for a in self.accounts):
            raise ValueError(f"label already exists: {label}")
        acct = WalletAccount(
            label=label,
            address=pubkey_to_address(keypair.public_key_hex),
            public_key_hex=keypair.public_key_hex,
            private_key_hex=keypair.private_key_hex,
            created_at=time.time(),
            path=path,
        )
        self.accounts.append(acct)
        self.save()
        return acct

    def create(self, label: str = "default") -> WalletAccount:
        """Derive the next account from the seed. Makes a seed phrase first if there is none."""
        if any(a.label == label for a in self.accounts):
            raise ValueError(f"label already exists: {label}")
        if not self.mnemonic:
            self.init_seed()
        path = hd.account_path(self.network.coin_type, self._next_account_index())
        return self._add(label, hd.derive_keypair(self._seed(), path), path)

    def restore(self, mnemonic: str, accounts: int = 1) -> list[WalletAccount]:
        """Restore from a seed phrase into an empty wallet: derives accounts 0..accounts-1."""
        if self.mnemonic or self.accounts:
            raise WalletError(f"{self.path} is not empty; restore into a new wallet file")
        if accounts < 1:
            raise WalletError("accounts must be >= 1")
        self.init_seed(mnemonic)
        seed = self._seed()
        out = []
        for i in range(accounts):
            path = hd.account_path(self.network.coin_type, i)
            out.append(self._add("default" if i == 0 else f"account-{i}", hd.derive_keypair(seed, path), path))
        return out

    def import_keypair(self, label: str, keypair: Keypair) -> WalletAccount:
        return self._add(label, keypair, path="")

    def get(self, label: str | None = None, address: str | None = None) -> WalletAccount:
        if label:
            for a in self.accounts:
                if a.label == label:
                    return a
            raise KeyError(label)
        if address:
            if not is_valid_address(address):
                raise ValueError(f"invalid address: {address}")
            for a in self.accounts:
                if a.address == address:
                    return a
            raise KeyError(address)
        if not self.accounts:
            raise KeyError("wallet empty")
        return self.accounts[0]

    def keypair(self, label: str = "default") -> Keypair:
        acct = self.get(label=label)
        return Keypair(acct.private_key_hex, acct.public_key_hex)

    def list_addresses(self) -> list[str]:
        return [a.address for a in self.accounts]

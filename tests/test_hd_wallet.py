"""Seed phrases (BIP-39), Ed25519 derivation (SLIP-0010), networks, wallet store v2."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haruhi_wallet import bip39, hd, network
from haruhi_wallet.address import is_valid_address, pubkey_to_address
from haruhi_wallet.keys import generate_keypair
from haruhi_wallet.store import WalletError, WalletStore

ABANDON_12 = " ".join(["abandon"] * 11 + ["about"])


class Bip39Tests(unittest.TestCase):
    def test_official_vector(self) -> None:
        # bip-0039 test vectors (trezor/python-mnemonic vectors.json), passphrase "TREZOR".
        self.assertEqual(bip39.entropy_to_mnemonic(bytes(16)), ABANDON_12)
        self.assertEqual(
            bip39.mnemonic_to_seed(ABANDON_12, "TREZOR").hex(),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553"
            "1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        )
        self.assertEqual(
            bip39.entropy_to_mnemonic(bytes.fromhex("7f" * 16)),
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
        )

    def test_roundtrip_and_checksum(self) -> None:
        phrase = bip39.generate_mnemonic(24)
        self.assertEqual(len(phrase.split()), 24)
        self.assertEqual(len(bip39.mnemonic_to_entropy(phrase)), 32)
        with self.assertRaises(bip39.MnemonicError):
            bip39.mnemonic_to_entropy(" ".join(["abandon"] * 12))  # bad checksum
        with self.assertRaises(bip39.MnemonicError):
            bip39.mnemonic_to_entropy(ABANDON_12.replace("about", "aboot"))


class Slip10Tests(unittest.TestCase):
    def test_official_vector_1(self) -> None:
        # SLIP-0010 test vector 1 for ed25519.
        seed = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        key, chain = hd.master_key(seed)
        self.assertEqual(chain.hex(), "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb")
        self.assertEqual(key.hex(), "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7")
        self.assertEqual(
            hd.derive_private_key(seed, "m/0'").hex(),
            "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3",
        )

    def test_hardened_only(self) -> None:
        with self.assertRaises(ValueError):
            hd.parse_path("m/44'/1031'/0")

    def test_coin_types_differ(self) -> None:
        seed = bip39.mnemonic_to_seed(ABANDON_12)
        main = hd.derive_private_key(seed, hd.account_path(1031, 0))
        test = hd.derive_private_key(seed, hd.account_path(1, 0))
        self.assertNotEqual(main, test)


class NetworkTests(unittest.TestCase):
    def test_prefix_per_network(self) -> None:
        pub = generate_keypair(bytes(32)).public_key_hex
        with mock.patch.dict(os.environ, {"NETWORK": "mainnet"}):
            main_addr = pubkey_to_address(pub)
            self.assertTrue(main_addr.startswith("haruhi1"))
            self.assertTrue(is_valid_address(main_addr))
        with mock.patch.dict(os.environ, {"NETWORK": "testnet"}):
            test_addr = pubkey_to_address(pub)
            self.assertTrue(test_addr.startswith("testhrh1"))
            self.assertTrue(is_valid_address(test_addr))
            self.assertFalse(is_valid_address(main_addr))  # wrong network is rejected
            self.assertTrue(network.looks_like_address(main_addr))

    def test_unknown_network(self) -> None:
        with mock.patch.dict(os.environ, {"NETWORK": "mainnett"}):
            with self.assertRaises(ValueError):
                network.current()


class StoreV2Tests(unittest.TestCase):
    def test_create_uses_seed_and_restore_matches(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = WalletStore(Path(tmp) / "a.json")
            first = store.create("default")
            second = store.create("miner")
            self.assertEqual(first.path, "m/44'/1'/0'")
            self.assertEqual(second.path, "m/44'/1'/1'")
            restored = WalletStore(Path(tmp) / "b.json").restore(store.mnemonic, accounts=2)
            self.assertEqual([a.address for a in restored], [first.address, second.address])
            self.assertEqual(restored[1].private_key_hex, second.private_key_hex)

    def test_restore_refuses_non_empty(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = WalletStore(Path(tmp) / "a.json")
            store.create()
            with self.assertRaises(WalletError):
                store.restore(ABANDON_12)

    def test_network_mismatch_refused(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "w.json"
            with mock.patch.dict(os.environ, {"NETWORK": "testnet"}):
                WalletStore(p).create()
            with mock.patch.dict(os.environ, {"NETWORK": "regtest"}):
                WalletStore(p)  # same prefix and keys: allowed
            with mock.patch.dict(os.environ, {"NETWORK": "mainnet"}):
                with self.assertRaises(WalletError):
                    WalletStore(p)

    def test_version1_file_loads_as_imported(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "old.json"
            kp = generate_keypair()
            p.write_text(json.dumps({"coin": "haruhi", "accounts": [{
                "label": "old", "address": pubkey_to_address(kp.public_key_hex),
                "public_key_hex": kp.public_key_hex, "private_key_hex": kp.private_key_hex,
                "created_at": 0.0}]}), encoding="utf-8")
            store = WalletStore(p)
            self.assertEqual(store.get(label="old").path, "")
            self.assertFalse(store.has_seed())
            new = store.create("new")  # adds a seed; old key stays imported
            self.assertEqual(new.path, "m/44'/1'/0'")
            self.assertEqual(store.get(label="old").path, "")


if __name__ == "__main__":
    unittest.main()

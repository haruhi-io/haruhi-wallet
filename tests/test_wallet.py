"""Wallet address format + store."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from haruhi_wallet.address import generate_keypair, is_valid_address, pubkey_to_address
from haruhi_wallet.keys import generate_keypair as gen_kp, sign_message, verify_message
from haruhi_wallet.store import WalletStore


class WalletTests(unittest.TestCase):
    def test_address_roundtrip(self) -> None:
        kp, addr = generate_keypair()
        self.assertTrue(addr.startswith("testhrh1"))  # default NETWORK=regtest
        self.assertTrue(is_valid_address(addr))
        self.assertEqual(pubkey_to_address(kp.public_key_hex), addr)

    def test_rejects_garbage(self) -> None:
        self.assertFalse(is_valid_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))
        self.assertFalse(is_valid_address("haruhi1invalid"))
        self.assertFalse(is_valid_address("testhrh1invalid"))
        self.assertFalse(is_valid_address(""))

    def test_store_create(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = WalletStore(Path(tmp) / "wallet.json")
            acct = store.create("miner")
            self.assertTrue(is_valid_address(acct.address))
            self.assertEqual(store.get(label="miner").address, acct.address)
            store2 = WalletStore(Path(tmp) / "wallet.json")
            self.assertEqual(store2.get(label="miner").address, acct.address)

    def test_sign_verify(self) -> None:
        kp = gen_kp()
        sig = sign_message(kp, b"hello haruhi")
        self.assertTrue(verify_message(kp.public_key_hex, b"hello haruhi", sig))
        self.assertFalse(verify_message(kp.public_key_hex, b"tampered", sig))

if __name__ == "__main__":
    unittest.main()
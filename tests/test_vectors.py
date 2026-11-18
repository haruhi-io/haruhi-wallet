"""Fixed test vectors: seed phrase -> keys -> addresses -> a signed transfer.

tests/vectors.json is the reference. haruhi-wallet.html embeds the same
vectors and checks itself against them every time it opens; the last test
here makes sure the two copies never drift apart.
"""

from __future__ import annotations

import json
import os
import re
import unittest
from pathlib import Path
from unittest import mock

from haruhi_wallet import bip39, hd
from haruhi_wallet.address import pubkey_to_address
from haruhi_wallet.keys import sign_message, verify_message
from haruhi_wallet.tx import TransferTx, verify_transfer

ROOT = Path(__file__).resolve().parent.parent
VECTORS = json.loads((ROOT / "tests" / "vectors.json").read_text(encoding="utf-8"))


class VectorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = bip39.mnemonic_to_seed(VECTORS["mnemonic"], VECTORS["passphrase"])

    def test_accounts(self) -> None:
        for acct in VECTORS["accounts"]:
            with self.subTest(path=acct["path"]), mock.patch.dict(os.environ, {"NETWORK": acct["network"]}):
                kp = hd.derive_keypair(self.seed, acct["path"])
                if "private_key_hex" in acct:
                    self.assertEqual(kp.private_key_hex, acct["private_key_hex"])
                self.assertEqual(kp.public_key_hex, acct["public_key_hex"])
                self.assertEqual(pubkey_to_address(kp.public_key_hex), acct["address"])

    def test_transfer(self) -> None:
        v = VECTORS["transfer"]
        with mock.patch.dict(os.environ, {"NETWORK": v["network"]}):
            kp = hd.derive_keypair(self.seed, v["from_path"])
            tx = TransferTx(
                from_address=v["from_address"],
                to_address=v["to_address"],
                atoms=v["atoms"],
                fee_atoms=v["fee_atoms"],
                nonce=v["nonce"],
                public_key_hex=kp.public_key_hex,
                created_at=v["created_at"],
            )
            self.assertEqual(tx.signing_payload().decode(), v["signing_payload"])
            sig = sign_message(kp, tx.signing_payload())  # Ed25519 is deterministic
            self.assertEqual(sig.hex(), v["signature_hex"])
            tx.signature_hex = sig.hex()
            tx.txid = tx.compute_txid()
            self.assertEqual(tx.txid, v["txid"])
            self.assertTrue(verify_message(kp.public_key_hex, tx.signing_payload(), sig))
            self.assertTrue(verify_transfer(tx).ok)

    def test_html_embeds_the_same_vectors(self) -> None:
        html = (ROOT / "haruhi-wallet.html").read_text(encoding="utf-8")
        m = re.search(r'<script type="application/json" id="vectors">(.*?)</script>', html, re.S)
        self.assertIsNotNone(m, "haruhi-wallet.html has no embedded vectors block")
        self.assertEqual(json.loads(m.group(1)), VECTORS)


if __name__ == "__main__":
    unittest.main()

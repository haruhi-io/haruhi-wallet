"""Signed account-model transfers."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass

from pydantic import BaseModel, Field

from haruhi_wallet.address import AddressError, address_payload, is_valid_address, pubkey_hash
from haruhi_wallet.keys import Keypair, sign_message, verify_message


class TransferTx(BaseModel):
    txid: str = ""
    from_address: str
    to_address: str
    atoms: int
    fee_atoms: int = 0
    nonce: int
    public_key_hex: str
    signature_hex: str = ""
    created_at: float = Field(default_factory=time.time)

    def signing_payload(self) -> bytes:
        body = {
            "from_address": self.from_address,
            "to_address": self.to_address,
            "atoms": self.atoms,
            "fee_atoms": self.fee_atoms,
            "nonce": self.nonce,
            "public_key_hex": self.public_key_hex,
            "created_at": self.created_at,
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()

    def compute_txid(self) -> str:
        return hashlib.sha256(self.signing_payload() + bytes.fromhex(self.signature_hex or "00")).hexdigest()


@dataclass
class TxValidationResult:
    ok: bool
    error: str = ""


def build_signed_transfer(
    *,
    keypair: Keypair,
    from_address: str,
    to_address: str,
    atoms: int,
    nonce: int,
    fee_atoms: int = 0,
) -> TransferTx:
    if atoms <= 0:
        raise ValueError("atoms must be positive")
    if fee_atoms < 0:
        raise ValueError("fee_atoms must be >= 0")
    if not is_valid_address(from_address) or not is_valid_address(to_address):
        raise AddressError("invalid haruhi address")
    if pubkey_hash(keypair.public_key) != address_payload(from_address):
        raise AddressError("keypair does not match from_address")

    tx = TransferTx(
        from_address=from_address,
        to_address=to_address,
        atoms=atoms,
        fee_atoms=fee_atoms,
        nonce=nonce,
        public_key_hex=keypair.public_key_hex,
    )
    sig = sign_message(keypair, tx.signing_payload())
    tx.signature_hex = sig.hex()
    tx.txid = tx.compute_txid()
    return tx


def verify_transfer(tx: TransferTx) -> TxValidationResult:
    if not is_valid_address(tx.from_address) or not is_valid_address(tx.to_address):
        return TxValidationResult(False, "invalid address")
    if tx.atoms <= 0:
        return TxValidationResult(False, "atoms must be positive")
    if tx.fee_atoms < 0:
        return TxValidationResult(False, "negative fee")
    if tx.from_address == tx.to_address:
        return TxValidationResult(False, "self-transfer forbidden")
    try:
        expected = address_payload(tx.from_address)
    except AddressError as exc:
        return TxValidationResult(False, str(exc))
    if pubkey_hash(bytes.fromhex(tx.public_key_hex)) != expected:
        return TxValidationResult(False, "public key does not match from_address")
    if not tx.signature_hex:
        return TxValidationResult(False, "missing signature")
    if not verify_message(tx.public_key_hex, tx.signing_payload(), bytes.fromhex(tx.signature_hex)):
        return TxValidationResult(False, "bad signature")
    if not tx.txid:
        return TxValidationResult(False, "missing txid")
    if tx.compute_txid() != tx.txid:
        return TxValidationResult(False, "txid mismatch")
    return TxValidationResult(True)
"""CLI: haruhi-wallet create|restore|seed|address|list|balance|validate|send|history"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx

from haruhi_wallet.address import is_valid_address
from haruhi_wallet.store import WalletStore

ATOMS_PER_COIN = 100_000_000


DEFAULT_WALLET_PATH = Path.home() / ".haruhi" / "wallet.json"


def _store(path: str | None) -> WalletStore:
    return WalletStore(path or os.getenv("WALLET_PATH") or DEFAULT_WALLET_PATH)


_SEED_WARNING = (
    "WRITE THESE WORDS DOWN, in order, and keep them offline. They restore every\n"
    "account in this wallet. Anyone who sees them can spend your coins."
)


def cmd_create(args: argparse.Namespace) -> None:
    store = _store(args.wallet)
    new_seed = not store.has_seed()
    acct = store.create(args.label)
    if new_seed:
        print(f"{_SEED_WARNING}\n\n  {store.mnemonic}\n", file=sys.stderr)
    print(json.dumps({"label": acct.label, "address": acct.address, "path": acct.path}, indent=2))


def cmd_restore(args: argparse.Namespace) -> None:
    store = _store(args.wallet)
    phrase = args.phrase or input("Seed phrase: ")
    accts = store.restore(phrase, accounts=args.accounts)
    rows = [{"label": a.label, "address": a.address, "path": a.path} for a in accts]
    print(json.dumps(rows, indent=2))


def cmd_seed(args: argparse.Namespace) -> None:
    store = _store(args.wallet)
    if not store.has_seed():
        raise SystemExit("this wallet has no seed phrase (made before seed phrases, or empty)")
    print(f"{_SEED_WARNING}\n", file=sys.stderr)
    print(store.mnemonic)


def cmd_address(args: argparse.Namespace) -> None:
    store = _store(args.wallet)
    acct = store.get(label=args.label)
    print(acct.address)


def cmd_list(args: argparse.Namespace) -> None:
    store = _store(args.wallet)
    rows = [{"label": a.label, "address": a.address} for a in store.accounts]
    print(json.dumps(rows, indent=2))


def cmd_balance(args: argparse.Namespace) -> None:
    store = _store(args.wallet)
    if args.address:
        address = args.address
        if not is_valid_address(address):
            raise SystemExit(f"invalid haruhi address: {address}")
    else:
        address = store.get(label=args.label).address

    chain = (args.chain or os.getenv("CHAIN_URL", "http://127.0.0.1:8332")).rstrip("/")
    with httpx.Client(timeout=5.0) as client:
        resp = client.get(f"{chain}/wallet/balance/{address}")
        resp.raise_for_status()
        atoms = int(resp.json().get("atoms", 0))

    print(
        json.dumps(
            {
                "address": address,
                "atoms": atoms,
                "coins": atoms / ATOMS_PER_COIN,
            },
            indent=2,
        )
    )


def cmd_validate(args: argparse.Namespace) -> None:
    ok = is_valid_address(args.address)
    print(json.dumps({"address": args.address, "valid": ok}))
    raise SystemExit(0 if ok else 1)


def cmd_send(args: argparse.Namespace) -> None:
    from haruhi_wallet.keys import Keypair
    from haruhi_wallet.tx import build_signed_transfer

    store = _store(args.wallet)
    acct = store.get(label=args.label)
    to_address = args.to
    if not is_valid_address(to_address):
        # allow sending to a local label
        try:
            to_address = store.get(label=args.to).address
        except KeyError as exc:
            raise SystemExit(f"invalid to address/label: {args.to}") from exc

    chain = (args.chain or os.getenv("CHAIN_URL", "http://127.0.0.1:8332")).rstrip("/")
    atoms = int(round(float(args.coins) * ATOMS_PER_COIN)) if args.coins is not None else int(args.atoms)
    fee_atoms = int(round(float(args.fee_coins) * ATOMS_PER_COIN)) if args.fee_coins is not None else int(args.fee_atoms)

    with httpx.Client(timeout=10.0) as client:
        nonce_resp = client.get(f"{chain}/wallet/nonce/{acct.address}")
        nonce_resp.raise_for_status()
        nonce = int(nonce_resp.json()["nonce"])
        kp = Keypair(acct.private_key_hex, acct.public_key_hex)
        tx = build_signed_transfer(
            keypair=kp,
            from_address=acct.address,
            to_address=to_address,
            atoms=atoms,
            nonce=nonce,
            fee_atoms=fee_atoms,
        )
        resp = client.post(f"{chain}/tx/send", json=tx.model_dump())
        if resp.status_code >= 400:
            raise SystemExit(resp.text)
        print(json.dumps(resp.json(), indent=2))


def cmd_history(args: argparse.Namespace) -> None:
    store = _store(args.wallet)
    address = args.address or store.get(label=args.label).address
    chain = (args.chain or os.getenv("CHAIN_URL", "http://127.0.0.1:8332")).rstrip("/")
    with httpx.Client(timeout=10.0) as client:
        resp = client.get(f"{chain}/wallet/history/{address}", params={"limit": args.limit})
        resp.raise_for_status()
        print(json.dumps(resp.json(), indent=2))


def _add_wallet_path(p: argparse.ArgumentParser) -> None:
    p.add_argument("--wallet", help="Path to wallet.json")


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="haruhi-wallet", description="Haruhi (HRH) wallet")
    parser.add_argument("--wallet", help="Path to wallet.json")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="Create a new account (makes a seed phrase the first time)")
    _add_wallet_path(p_create)
    p_create.add_argument("--label", default="default")
    p_create.set_defaults(func=cmd_create)

    p_restore = sub.add_parser("restore", help="Restore a wallet from a seed phrase into a new file")
    _add_wallet_path(p_restore)
    p_restore.add_argument("--phrase", help="Seed phrase (omit to type it at a prompt, keeping it out of shell history)")
    p_restore.add_argument("--accounts", type=int, default=1, help="How many accounts to derive (default 1)")
    p_restore.set_defaults(func=cmd_restore)

    p_seed = sub.add_parser("seed", help="Show this wallet's seed phrase")
    _add_wallet_path(p_seed)
    p_seed.set_defaults(func=cmd_seed)

    p_addr = sub.add_parser("address", help="Show address for a label")
    _add_wallet_path(p_addr)
    p_addr.add_argument("--label", default="default")
    p_addr.set_defaults(func=cmd_address)

    p_list = sub.add_parser("list", help="List accounts")
    _add_wallet_path(p_list)
    p_list.set_defaults(func=cmd_list)

    p_bal = sub.add_parser("balance", help="Show balance")
    _add_wallet_path(p_bal)
    p_bal.add_argument("--label", default="default")
    p_bal.add_argument("--address")
    p_bal.add_argument("--chain", help="Chain node base URL")
    p_bal.set_defaults(func=cmd_balance)

    p_val = sub.add_parser("validate", help="Validate address format")
    p_val.add_argument("address")
    p_val.set_defaults(func=cmd_validate)

    p_send = sub.add_parser("send", help="Sign and broadcast a transfer")
    _add_wallet_path(p_send)
    p_send.add_argument("--label", default="default", help="Sender label")
    p_send.add_argument("--to", required=True, help="Destination address (haruhi1… on mainnet, testhrh1… on testnet) or local label")
    p_send.add_argument("--coins", type=float, help="Amount in coins")
    p_send.add_argument("--atoms", type=int, default=0, help="Amount in atoms (if --coins omitted)")
    p_send.add_argument("--fee-coins", type=float, dest="fee_coins")
    p_send.add_argument("--fee-atoms", type=int, default=0, dest="fee_atoms")
    p_send.add_argument("--chain", help="Chain node base URL")
    p_send.set_defaults(func=cmd_send)

    p_hist = sub.add_parser("history", help="Show transfer history")
    _add_wallet_path(p_hist)
    p_hist.add_argument("--label", default="default")
    p_hist.add_argument("--address")
    p_hist.add_argument("--chain")
    p_hist.add_argument("--limit", type=int, default=20)
    p_hist.set_defaults(func=cmd_history)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
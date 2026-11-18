# Haruhi Wallet

Wallet for [Haruhi](https://haruhi.io) (HRH), the proof-of-useful-work coin.
It comes in two forms that derive the same keys and addresses:

| | What it is | Use it for |
|---|---|---|
| [`haruhi-wallet.html`](haruhi-wallet.html) | One self-contained HTML file. No installs, no network access. | Cold storage: create a seed phrase offline, print a paper wallet, check a backup, sign transfers offline |
| [`haruhi_wallet/`](haruhi_wallet/) | Python package and `haruhi-wallet` command | Everyday use against a node: balance, send, history |

> Haruhi is pre-launch. There is no public network yet and no coins in
> circulation. Mainnet addresses can be made today and will be valid at launch.

## Offline HTML wallet (cold storage)

1. Download `haruhi-wallet.html` from a tagged release of this repository.
2. Move it to a computer that is offline (or will never connect), and open it in
   a current browser (Chrome, Edge, Firefox or Safari).
3. The page runs a self-test against the reference vectors below every time it
   opens. Its buttons stay disabled unless every check passes.
4. **New wallet** makes a 24-word seed phrase and its addresses. Write the words
   on paper, or use **Print paper wallet** with a printer that is not networked.
5. Clear the page, open **Check a seed phrase**, type the words back in and make
   sure you get the same addresses. Only then send coins to them.
6. To spend, look up the address's next nonce on an online computer
   (`GET <node>/wallet/nonce/<address>`). Then use **Sign a transfer** offline and
   carry the signed JSON back to broadcast it:
   `curl -X POST <node>/tx/send -H "Content-Type: application/json" -d @tx.json`.
   The signed JSON contains no secret.

The page's Content Security Policy is `connect-src 'none'`, so it cannot send
anything anywhere, even if it is opened online. It uses the browser's WebCrypto
for SHA-256, HMAC-SHA512, PBKDF2 and Ed25519, and loads no outside code. The
BIP-39 word list is embedded and checked against its official SHA-256.

## Python wallet

```bash
pip install .                      # Python 3.10+
export NETWORK=mainnet             # or testnet / regtest (the default)
haruhi-wallet create               # prints the seed phrase once, on stderr
haruhi-wallet restore              # prompts for a seed phrase
haruhi-wallet list
haruhi-wallet balance --chain http://<node>:8332
haruhi-wallet send --to haruhi1… --coins 1.5 --fee-coins 0.00001 --chain http://<node>:8332
```

The wallet file defaults to `~/.haruhi/wallet.json` (override with `--wallet` or
`WALLET_PATH`). It holds the seed phrase **in plaintext**, so protect it, or keep
your funds in cold storage instead.

## Specification

| Item | Value |
|---|---|
| Seed phrase | [BIP-39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki), English word list, empty passphrase |
| Key type | Ed25519 ([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)) |
| Derivation | [SLIP-0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md) for Ed25519. Every step is hardened. |
| Path | `m/44'/1031'/<account>'` on mainnet ([SLIP-0044](https://github.com/satoshilabs/slips/blob/master/slip-0044.md) coin type **1031**), `m/44'/1'/<account>'` on testnet and regtest |
| Address | bech32 ([BIP-173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki)) with witness version 0. The program is the first 20 bytes of SHA-256(public key). |
| Address prefix | `haruhi` on mainnet (`haruhi1q…`), `testhrh` on testnet and regtest ([SLIP-0173](https://github.com/satoshilabs/slips/blob/master/slip-0173.md)) |
| Amounts | 1 HRH = 100,000,000 atoms |
| Transfer signature | Ed25519 over the canonical JSON (sorted keys, separators `,` `:`) of `atoms, created_at, fee_atoms, from_address, nonce, public_key_hex, to_address` |
| Transaction id | SHA-256(signing payload ‖ signature), hex |

One key per account (the layout Stellar uses), so each account has a single address.

## Test vectors

Seed phrase `abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about`, no passphrase:

| Network | Path | Public key | Address |
|---|---|---|---|
| mainnet | `m/44'/1031'/0'` | `7a77356f2b881ab4c55d3b109d75ea8c9a3f9cabf2c6ed3abf3906f898d8d848` | `haruhi1qehl7hqvxyn32q7ks3nw4kgf9zm32cp3vl5946j` |
| mainnet | `m/44'/1031'/1'` | `8b153470e18fe3d60437364f64de459eec62cf06752fb9cd5810cf56ec2e6559` | `haruhi1qa7hn9ndz9ztk0z0cl9rxw6caszx8xjst9tspma` |
| testnet | `m/44'/1'/0'` | `a90eb13b090b4d4c31ae87d864c0cd8db25216c90c1ce6fbfd04ddcdc1aa110c` | `testhrh1qfd6fmfa6ykka7qtqrmsk6wm0rmkfvqlan9z6ph` |

The full set, including private keys and a signed transfer, is in
[`tests/vectors.json`](tests/vectors.json). The Python tests and the HTML
self-test both check against it, and a test fails if the copy embedded in the
HTML file drifts from it.

```bash
python -m unittest discover -s tests -t .
```

**Never send coins to the test-vector addresses.** Their private keys are public.

## License

Apache-2.0. See [LICENSE](LICENSE).

# Zero Width

A local workbench and CLI for Oversec-style zero-width steganography. Hide a
message inside invisible characters, paste the carrier into a post, and reveal
it later with the same password.

This is a compatible reimplementation of Oversec's `zwidthbmp` + `SIMPLESYM`
formats, not an official Oversec product. It preserves the format's quirks so
real messages decrypt, including the missing ciphertext byte in the supplied
sample tweet.

Source code: <https://github.com/zoasr/oversec-stego>

## Original Oversec sources

This project is an independent reimplementation. The original implementation is
open source (GPL-3.0); see those repositories for their licensing terms:

- [oversecio/oversec](https://github.com/oversecio/oversec) — the Android app.
- [oversecio/oversec_crypto](https://github.com/oversecio/oversec_crypto) — the
  crypto library that defines the formats reproduced here.

Specific upstream references:

| Behaviour reproduced here | Upstream source |
| --- | --- |
| Zero-width byte mapping, `OSC` magic, spread/filler | [`ZeroWidthXCoder.kt`](https://github.com/oversecio/oversec_crypto/blob/master/crypto/src/main/java/io/oversec/one/crypto/encoding/ZeroWidthXCoder.kt) |
| bcrypt password/key derivation and the repeated-half key quirk | [`KeyUtil.kt`](https://github.com/oversecio/oversec_crypto/blob/master/crypto/src/main/java/io/oversec/one/crypto/symbase/KeyUtil.kt) |
| ChaCha20 + Poly1305 framing | [`OversecChacha20Poly1305.kt`](https://github.com/oversecio/oversec_crypto/blob/master/crypto/src/main/java/io/oversec/one/crypto/symbase/OversecChacha20Poly1305.kt) |
| SIMPLESYM envelope handling | [`SimpleSymmetricCryptoHandler.kt`](https://github.com/oversecio/oversec_crypto/blob/master/crypto/src/main/java/io/oversec/one/crypto/symsimple/SimpleSymmetricCryptoHandler.kt) |
| protobuf messages | [`inner.proto`](https://github.com/oversecio/oversec_crypto/blob/master/crypto/src/main/proto/inner.proto), [`outer.proto`](https://github.com/oversecio/oversec_crypto/blob/master/crypto/src/main/proto/outer.proto) |
| raw bcrypt used by `bcrypt_sc.c` | SpongyCastle [`BCrypt.java`](https://github.com/rtyley/spongycastle/blob/spongy-master/core/src/main/java/org/spongycastle/crypto/generators/BCrypt.java) |

Upstream references were read from `oversecio/oversec_crypto` commit
[`9040ab6`](https://github.com/oversecio/oversec_crypto/commit/9040ab646c7ab1ec9d1e2fff05782e07b5547547).

## Run the web app

Do **not** open `index.html` directly. The page needs the local API, so opening
it as a file makes the browser block its requests.

From this folder:

```bash
python server.py --open
```

Then use <http://127.0.0.1:8765/>. On Windows you can also double-click
`start.bat`; on Linux/macOS run `./start.sh`, which starts the server through
`uv` and installs the dependencies automatically.

You can also run it directly with uv:

```bash
uv run --with-requirements requirements.txt -- python server.py --open
```

The server binds to loopback only, stores nothing, and makes no external
requests. The fonts are self-hosted.

### Sample tweet

Choose **Try the sample**, then **Reveal message**. The password is `Rg111`.
The sample is one ciphertext byte short; the decoder finds the missing `0x0f`
at offset 16 and verifies the Poly1305 tag.

## Run the CLI

Decrypt the built-in sample:

```bash
uv run --with-requirements requirements.txt -- python oversec_stego.py decrypt --sample
```

Hide a message:

```bash
uv run --with-requirements requirements.txt -- python oversec_stego.py encrypt --password "your password" --message "meet me at midnight" --output hidden.txt
```

Reveal it:

```bash
uv run --with-requirements requirements.txt -- python oversec_stego.py decrypt --password "your password" --text-file hidden.txt
```

Use `--json` on either command for machine-readable metadata. Run
`uv run --with-requirements requirements.txt -- python oversec_stego.py --help`
for every option.

## Requirements

- Python 3.10 or newer
- [`uv`](https://docs.astral.sh/uv/) (recommended; it manages `pycryptodome` for you)
- `pycryptodome` (installed automatically by `uv run --with-requirements requirements.txt`)

`bcrypt_sc.dll` / `libbcrypt_sc.so` / `libbcrypt_sc.dylib` is a small native
helper that reproduces SpongyCastle's raw bcrypt exactly. The loader picks the
file for the current platform. If it is missing or cannot load, the Python
fallback is used and key derivation is slower. The C source is in
`bcrypt_sc.c`; on Linux build it with:

```bash
cc -O2 -shared -fPIC -o libbcrypt_sc.so bcrypt_sc.c
```

## Tests

```bash
uv run --with-requirements requirements.txt -- python -m unittest discover -s tests -v
```

The suite covers the sample repair, Poly1305 verification, protobuf framing,
the zero-width mapping, the CLI core, and the HTTP API.

## Layout

| File | Purpose |
| --- | --- |
| `core.py` | Crypto, protobuf, zero-width mapping, sample repair |
| `bcrypt_sc.py` | SpongyCastle-compatible bcrypt wrapper |
| `oversec_stego.py` | CLI |
| `server.py` | Local HTTP API and static server |
| `index.html`, `styles.css`, `app.js` | Web workbench |
| `fonts.css`, `fonts/` | Self-hosted Latin font subsets |
| `tests/` | Unit and server tests |

## Privacy

Messages, passwords, and derived keys stay in the Python process. The server
has no analytics, no database, and no outbound network calls. The browser talks
only to `127.0.0.1`.

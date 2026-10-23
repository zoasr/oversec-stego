# Zero Width

A local workbench and CLI for Oversec-style zero-width steganography. Hide a
message inside invisible characters, paste the carrier into a post, and reveal
it later with the same password.

This is a compatible reimplementation of Oversec's `zwidthbmp` + `SIMPLESYM`
formats, not an official Oversec product. It preserves the format's quirks so
real messages decrypt, including the missing ciphertext byte in the supplied
sample tweet.

## Run the web app

Do **not** open `index.html` directly. The page needs the local API, so opening
it as a file makes the browser block its requests.

From this folder:

```powershell
python server.py --open
```

Then use <http://127.0.0.1:8765/>. On Windows you can also double-click
`start.bat`.

The server binds to loopback only, stores nothing, and makes no external
requests. The fonts are self-hosted.

### Sample tweet

Choose **Try the sample**, then **Reveal message**. The password is `Rg111`.
The sample is one ciphertext byte short; the decoder finds the missing `0x0f`
at offset 16 and verifies the Poly1305 tag.

## Run the CLI

Decrypt the built-in sample:

```powershell
python oversec_stego.py decrypt --sample
```

Hide a message:

```powershell
python oversec_stego.py encrypt --password "your password" --message "meet me at midnight" --output hidden.txt
```

Reveal it:

```powershell
python oversec_stego.py decrypt --password "your password" --text-file hidden.txt
```

Use `--json` on either command for machine-readable metadata. Run
`python oversec_stego.py --help` for every option.

## Requirements

- Python 3.10 or newer
- `pycryptodome` (`python -m pip install -r requirements.txt`)

`bcrypt_sc.dll` is a small Windows helper that reproduces SpongyCastle's raw
bcrypt exactly. If it is missing or cannot load, the Python fallback is used
and key derivation is slower. The C source is in `bcrypt_sc.c`.

## Tests

```powershell
python -m unittest discover -s tests -v
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

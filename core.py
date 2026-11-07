"""Oversec zero-width steganography, reimplemented.

This module implements the parts of Oversec's ``zwidthbmp`` + ``SIMPLESYM``
formats that are needed to hide and reveal a text message:

* SpongyCastle-compatible raw bcrypt key derivation
* the buggy Oversec message-key derivation (both halves repeat)
* ChaCha20 with an 8-byte IV, followed by a Poly1305 tag
* the small protobuf messages used by Oversec
* the zero-width byte mapping, with the ``OSC`` magic
* recovery of a single missing zero-width byte against the Poly1305 tag

The code is deliberately dependency-light: PyCryptodome for ChaCha20 and
Poly1305, the standard library for everything else. It is a compatible
reimplementation, not an official Oversec product.

Reference implementation (GPL-3.0), from the Oversec project:
https://github.com/oversecio/oversec_crypto

* ``encoding/ZeroWidthXCoder.kt``: zero-width mapping, ``OSC`` magic, fillers
* ``symbase/KeyUtil.kt``: bcrypt key derivation, including the repeated-half
  ``getEncryptionKey`` quirk
* ``symbase/OversecChacha20Poly1305.kt``: ChaCha20 + Poly1305 record framing
* ``symsimple/SimpleSymmetricCryptoHandler.kt``: SIMPLESYM envelope
* ``proto/inner.proto`` and ``proto/outer.proto``: protobuf messages
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Iterable, Optional

try:
    from Crypto.Cipher import ChaCha20
    from Crypto.Hash.Poly1305 import Poly1305_MAC
except ModuleNotFoundError as exc:  # pragma: no cover - depends on the interpreter
    if exc.name and exc.name.startswith("Crypto"):
        raise SystemExit(
            "PyCryptodome is required but is not installed for this Python.\n"
            "Install it with:\n"
            "  python3 -m pip install -r requirements.txt\n"
            "Or start the app with ./start.sh, which uses the local .venv."
        ) from exc
    raise

import bcrypt_sc


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC = b"OSC"
DEFAULT_CARRIER = "This post is exactly what it looks like."
COST_KEYHASH_DEFAULT = 5
MESSAGE_COST = 4
KEY_ID_COST = 6
PASSWORD_COST = 8

MAX_MESSAGE_CHARS = 100_000
MAX_CARRIER_CHARS = 10_000
MAX_REVEAL_CHARS = 200_000

SAMPLE_PASSWORD = "Rg111"
SAMPLE_CARRIER = DEFAULT_CARRIER
# The original 118-byte payload from the supplied tweet. It is one byte short
# inside the outer ciphertext; the missing byte is recovered against the tag.
SAMPLE_ENCODED_HEX = (
    "4f53437312710a6f0805126b093ce1a346f53f856c121090b7e8f790100eb6e0ad014080d9125a"
    "1a08403be053f74382e622440a67c889f1a92b58a6cdce75b16f679783abb8dc124223c78625c10b"
    "5ee5567b9507b6dca515e3c64d1b858fe9a289b3aa6c5c3816bf6c96b3ffdeb604fbaf0664e371"
)
SAMPLE_ENCODED = bytes.fromhex(SAMPLE_ENCODED_HEX)


# ---------------------------------------------------------------------------
# Errors and result types
# ---------------------------------------------------------------------------

class StegoError(Exception):
    """A user-facing failure with a stable machine code."""

    def __init__(self, code: str, message: str, field: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.field = field

    def as_dict(self) -> dict:
        out = {"code": self.code, "message": self.message}
        if self.field:
            out["field"] = self.field
        return out


@dataclass(frozen=True)
class EncryptResult:
    output: str
    meta: dict


@dataclass(frozen=True)
class DecryptResult:
    message: str
    meta: dict
    repaired: Optional[dict]


# ---------------------------------------------------------------------------
# Small protobuf reader/writer
# ---------------------------------------------------------------------------

class ProtoError(Exception):
    pass


@dataclass
class Field:
    number: int
    wire: int
    value: object
    declared_len: Optional[int] = None
    truncated: bool = False


def _encode_varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint cannot be negative")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _read_varint(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while pos < len(data):
        byte = data[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
        if shift > 63:
            raise ProtoError("varint is too long")
    raise ProtoError("truncated varint")


def _tag(number: int, wire: int) -> bytes:
    return _encode_varint((number << 3) | wire)


def _len_field(number: int, data: bytes) -> bytes:
    return _tag(number, 2) + _encode_varint(len(data)) + data


def _varint_field(number: int, value: int) -> bytes:
    return _tag(number, 0) + _encode_varint(value)


def _fixed64_field(number: int, value: int) -> bytes:
    return _tag(number, 1) + value.to_bytes(8, "little")


def _parse_fields(data: bytes, lenient: bool = True) -> list[Field]:
    """Parse protobuf fields, allowing only the final field to be short.

    Oversec's missing-zero-width-character sample is one byte short at the end
    of every enclosing length-delimited message. ``lenient`` lets us keep the
    available bytes and report the shortfall instead of failing immediately.
    """
    fields: list[Field] = []
    pos = 0
    while pos < len(data):
        tag, pos = _read_varint(data, pos)
        number = tag >> 3
        wire = tag & 0x07
        if number == 0:
            raise ProtoError("invalid field number 0")

        if wire == 0:
            value, pos = _read_varint(data, pos)
            fields.append(Field(number, wire, value))
        elif wire == 1:
            if pos + 8 > len(data):
                raise ProtoError("truncated fixed64")
            value = int.from_bytes(data[pos:pos + 8], "little")
            pos += 8
            fields.append(Field(number, wire, value))
        elif wire == 2:
            length, pos = _read_varint(data, pos)
            remaining = len(data) - pos
            if length > remaining:
                if not lenient:
                    raise ProtoError("truncated length-delimited field")
                fields.append(
                    Field(
                        number,
                        wire,
                        data[pos:],
                        declared_len=length,
                        truncated=True,
                    )
                )
                pos = len(data)
                break
            value = data[pos:pos + length]
            pos += length
            fields.append(Field(number, wire, value, declared_len=length))
        elif wire == 5:
            if pos + 4 > len(data):
                raise ProtoError("truncated fixed32")
            value = int.from_bytes(data[pos:pos + 4], "little")
            pos += 4
            fields.append(Field(number, wire, value))
        else:
            raise ProtoError(f"unsupported protobuf wire type {wire}")
    return fields


def _get_field(
    fields: Iterable[Field],
    number: int,
    wire: Optional[int] = None,
    *,
    required: bool = True,
) -> Optional[Field]:
    for field in fields:
        if field.number == number and (wire is None or field.wire == wire):
            return field
    if required:
        raise ProtoError(f"missing protobuf field {number}")
    return None


def _get_fields(fields: Iterable[Field], number: int, wire: Optional[int] = None) -> list[Field]:
    return [f for f in fields if f.number == number and (wire is None or f.wire == wire)]


# ---------------------------------------------------------------------------
# Oversec protobuf messages
# ---------------------------------------------------------------------------

@dataclass
class OuterEntry:
    keyhash: int
    salt: bytes
    iv: bytes
    ciphertext: bytes
    declared_len: int
    truncated: bool


@dataclass
class OuterMessage:
    cost_keyhash: int
    entries: list[OuterEntry]
    declared_len: int
    actual_len: int


def build_inner(text: str, padding: bytes = b"") -> bytes:
    """InnerData { TextAndPaddingV0 { text, padding } }."""
    text_bytes = text.encode("utf-8")
    text_and_padding = _len_field(1, text_bytes)
    if padding:
        text_and_padding += _len_field(2, padding)
    return _len_field(1, text_and_padding)


def parse_inner(data: bytes) -> tuple[str, bytes]:
    fields = _parse_fields(data, lenient=False)
    inner_field = _get_field(fields, 1, 2)
    assert inner_field is not None
    inner_fields = _parse_fields(inner_field.value, lenient=False)  # type: ignore[arg-type]
    text_field = _get_field(inner_fields, 1, 2)
    if text_field is None:
        raise ProtoError("missing inner text")
    padding_field = _get_field(inner_fields, 2, 2, required=False)
    try:
        text = bytes(text_field.value).decode("utf-8")  # type: ignore[arg-type]
    except UnicodeDecodeError as exc:
        raise ProtoError("inner text is not UTF-8") from exc
    padding = bytes(padding_field.value) if padding_field is not None else b""
    return text, padding


def build_outer(
    cost_keyhash: int,
    keyhash: int,
    salt: bytes,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    entry = (
        _fixed64_field(1, keyhash)
        + _len_field(2, salt)
        + _len_field(3, iv)
        + _len_field(4, ciphertext)
    )
    cha_cha = _varint_field(1, cost_keyhash) + _len_field(2, entry)
    sym = _len_field(1, cha_cha)
    return _len_field(2, sym)


def parse_outer(encoded: bytes) -> OuterMessage:
    """Parse the delimited Outer.Msg after the magic bytes."""
    outer_len, pos = _read_varint(encoded, 0)
    outer_bytes = encoded[pos:]
    outer_fields = _parse_fields(outer_bytes, lenient=True)

    sym_field = _get_field(outer_fields, 2, 2, required=False)
    if sym_field is None:
        sym_field = _get_field(outer_fields, 1, 2, required=False)
    if sym_field is None:
        raise ProtoError("no symmetric message in outer envelope")

    sym_fields = _parse_fields(sym_field.value, lenient=True)  # type: ignore[arg-type]
    cha_field = _get_field(sym_fields, 1, 2)
    if cha_field is None:
        raise ProtoError("no ChaCha message in symmetric envelope")

    cha_fields = _parse_fields(cha_field.value, lenient=True)  # type: ignore[arg-type]
    cost_field = _get_field(cha_fields, 1, 0)
    if cost_field is None:
        raise ProtoError("missing keyhash cost")
    cost_keyhash = int(cost_field.value)  # type: ignore[arg-type]

    entry_fields = _get_fields(cha_fields, 2, 2)
    if not entry_fields:
        raise ProtoError("no per-key ciphertext")

    entries: list[OuterEntry] = []
    for entry_field in entry_fields:
        fields = _parse_fields(entry_field.value, lenient=True)  # type: ignore[arg-type]
        keyhash_field = _get_field(fields, 1, 1)
        salt_field = _get_field(fields, 2, 2)
        iv_field = _get_field(fields, 3, 2)
        ct_field = _get_field(fields, 4, 2)
        if keyhash_field is None or salt_field is None or iv_field is None or ct_field is None:
            raise ProtoError("incomplete per-key ciphertext")
        entries.append(
            OuterEntry(
                keyhash=int(keyhash_field.value),  # type: ignore[arg-type]
                salt=bytes(salt_field.value),  # type: ignore[arg-type]
                iv=bytes(iv_field.value),  # type: ignore[arg-type]
                ciphertext=bytes(ct_field.value),  # type: ignore[arg-type]
                declared_len=int(ct_field.declared_len or len(ct_field.value)),  # type: ignore[arg-type]
                truncated=bool(ct_field.truncated),
            )
        )

    return OuterMessage(
        cost_keyhash=cost_keyhash,
        entries=entries,
        declared_len=outer_len,
        actual_len=len(outer_bytes),
    )


# ---------------------------------------------------------------------------
# Zero-width encoding
# ---------------------------------------------------------------------------

def byte_to_zero_width(byte: int) -> str:
    if 0 <= byte <= 0x0F:
        return chr(0xFE00 + byte)
    if 0x10 <= byte <= 0xFF:
        return chr(0xE0100 + byte - 0x10)
    raise ValueError("byte out of range")


def zero_width_to_byte(char: str) -> Optional[int]:
    codepoint = ord(char)
    if 0xFE00 <= codepoint <= 0xFE0F:
        return codepoint - 0xFE00
    if 0xE0100 <= codepoint <= 0xE01EF:
        return codepoint - 0xE0100 + 0x10
    return None


_REVERSE_ZERO_WIDTH = {
    ord(byte_to_zero_width(value)): value for value in range(256)
}
MAGIC_ZERO_WIDTH = "".join(byte_to_zero_width(b) for b in MAGIC)


def encode_zero_width(data: bytes, spread: int = 0, filler: str = " ") -> str:
    """Map bytes to zero-width characters, optionally breaking the run.

    Oversec's mapper inserts one padding character after more than ``spread``
    invisible characters. Its reader ignores one unmapped character between
    mapped ones, which is exactly what this does.
    """
    if spread < 0:
        raise ValueError("spread cannot be negative")
    out: list[str] = []
    count = 0
    for byte in data:
        out.append(byte_to_zero_width(byte))
        count += 1
        if spread and count > spread:
            out.append(filler)
            count = 0
    return "".join(out)


@dataclass
class DecodedZeroWidth:
    encoded: bytes
    char_count: int
    filler_count: int
    start_index: int


def decode_zero_width(text: str) -> DecodedZeroWidth:
    start = text.find(MAGIC_ZERO_WIDTH)
    if start < 0:
        raise StegoError(
            "no_payload",
            "No zero-width Oversec payload was found in that text.",
            field="text",
        )

    out = bytearray()
    filler_count = 0
    unmapped_streak = 0
    index = start
    while index < len(text):
        char = text[index]
        byte = _REVERSE_ZERO_WIDTH.get(ord(char))
        if byte is not None:
            out.append(byte)
            unmapped_streak = 0
        else:
            unmapped_streak += 1
            if unmapped_streak >= 2:
                break
            filler_count += 1
        index += 1

    if not out.startswith(MAGIC):
        raise StegoError("no_payload", "The zero-width payload has no OSC magic.", field="text")

    return DecodedZeroWidth(
        encoded=bytes(out),
        char_count=len(out),
        filler_count=filler_count,
        start_index=start,
    )


# ---------------------------------------------------------------------------
# ChaCha20 + Poly1305
# ---------------------------------------------------------------------------

def _clamped_key(key: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Poly1305 key must be 32 bytes")
    clamped = bytearray(key)
    clamped[3] &= 15
    clamped[7] &= 15
    clamped[11] &= 15
    clamped[15] &= 15
    clamped[4] &= 252
    clamped[8] &= 252
    clamped[12] &= 252
    return bytes(clamped)


def poly1305_tag(key: bytes, body: bytes) -> bytes:
    """Oversec's record MAC: body, zero pad to 16, little-endian length."""
    clamped = _clamped_key(key)
    mac = Poly1305_MAC(clamped[:16], clamped[16:], None)
    mac.update(body)
    partial = len(body) % 16
    if partial:
        mac.update(b"\x00" * (16 - partial))
    mac.update(len(body).to_bytes(8, "little"))
    return mac.digest()


def _encrypt_chacha(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    return ChaCha20.new(key=key, nonce=iv).encrypt(plaintext)


def _decrypt_chacha(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    return ChaCha20.new(key=key, nonce=iv).decrypt(ciphertext)


# ---------------------------------------------------------------------------
# Key derivation cache
# ---------------------------------------------------------------------------

_KEY_CACHE: "OrderedDict[bytes, tuple[bytes, int]]" = OrderedDict()
_KEY_CACHE_LOCK = threading.Lock()
_MSG_KEY_CACHE: "OrderedDict[tuple[int, bytes], bytes]" = OrderedDict()
_MSG_KEY_CACHE_LOCK = threading.Lock()


def _derive_password_key_cached(password: str) -> tuple[bytes, int]:
    cache_key = hashlib.sha256(password.encode("utf-8")).digest()
    with _KEY_CACHE_LOCK:
        cached = _KEY_CACHE.get(cache_key)
        if cached is not None:
            _KEY_CACHE.move_to_end(cache_key)
            return cached

    raw_key, key_id = bcrypt_sc.derive_password_key(password)

    with _KEY_CACHE_LOCK:
        _KEY_CACHE[cache_key] = (raw_key, key_id)
        _KEY_CACHE.move_to_end(cache_key)
        while len(_KEY_CACHE) > 8:
            _KEY_CACHE.popitem(last=False)
    return raw_key, key_id


def _message_key_cached(raw_key: bytes, key_id: int, salt: bytes) -> bytes:
    cache_key = (key_id, salt)
    with _MSG_KEY_CACHE_LOCK:
        cached = _MSG_KEY_CACHE.get(cache_key)
        if cached is not None:
            _MSG_KEY_CACHE.move_to_end(cache_key)
            return cached

    message_key = bcrypt_sc.get_encryption_key(raw_key, salt)

    with _MSG_KEY_CACHE_LOCK:
        _MSG_KEY_CACHE[cache_key] = message_key
        _MSG_KEY_CACHE.move_to_end(cache_key)
        while len(_MSG_KEY_CACHE) > 32:
            _MSG_KEY_CACHE.popitem(last=False)
    return message_key


def clear_caches() -> None:
    with _KEY_CACHE_LOCK:
        _KEY_CACHE.clear()
    with _MSG_KEY_CACHE_LOCK:
        _MSG_KEY_CACHE.clear()


# ---------------------------------------------------------------------------
# Encrypt / decrypt
# ---------------------------------------------------------------------------

def _bcrypt_meta(cost_keyhash: int) -> dict:
    return {
        "password_cost": PASSWORD_COST,
        "key_id_cost": KEY_ID_COST,
        "keyhash_cost": cost_keyhash,
        "message_cost": MESSAGE_COST,
    }


def encrypt(
    message: str,
    password: str,
    carrier: str = DEFAULT_CARRIER,
    *,
    spread: int = 0,
    padding_bytes: int = 6,
) -> EncryptResult:
    if not isinstance(message, str) or not message:
        raise StegoError("bad_request", "Enter a message to hide.", field="message")
    if len(message) > MAX_MESSAGE_CHARS:
        raise StegoError("too_large", "The message is too long.", field="message")
    if not isinstance(password, str) or not password:
        raise StegoError("bad_request", "Enter a password.", field="password")
    if not isinstance(carrier, str):
        raise StegoError("bad_request", "Carrier text must be text.", field="carrier")
    if len(carrier) > MAX_CARRIER_CHARS:
        raise StegoError("too_large", "The carrier text is too long.", field="carrier")
    if not (0 <= spread <= 10_000):
        raise StegoError("bad_request", "Spread must be between 0 and 10000.", field="spread")
    if not (0 <= padding_bytes <= 255):
        raise StegoError("bad_request", "Padding must be between 0 and 255 bytes.", field="padding")

    raw_key, key_id = _derive_password_key_cached(password)
    salt = secrets.token_bytes(16)
    iv = secrets.token_bytes(8)
    keyhash = bcrypt_sc.calc_session_key_id(key_id, salt, COST_KEYHASH_DEFAULT)
    message_key = _message_key_cached(raw_key, key_id, salt)

    padding = secrets.token_bytes(padding_bytes) if padding_bytes else b""
    inner = build_inner(message, padding)
    body = _encrypt_chacha(inner, message_key, iv)
    tag = poly1305_tag(message_key, body)
    ciphertext = body + tag

    outer = build_outer(COST_KEYHASH_DEFAULT, keyhash, salt, iv, ciphertext)
    encoded = MAGIC + _encode_varint(len(outer)) + outer
    hidden = encode_zero_width(encoded, spread=spread)
    output = f"{carrier.rstrip()} {hidden}" if carrier.strip() else hidden

    meta = {
        "operation": "encrypt",
        "format": "zwidthbmp",
        "kdf": "SIMPLESYM",
        "key_id": f"{key_id:016x}",
        "keyhash": f"{keyhash:016x}",
        "cost_keyhash": COST_KEYHASH_DEFAULT,
        "salt": salt.hex(),
        "iv": iv.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "ciphertext_len": len(ciphertext),
        "tag_hex": tag.hex(),
        "inner_len": len(inner),
        "padding_hex": padding.hex(),
        "padding_len": len(padding),
        "encoded_hex": encoded.hex(),
        "encoded_len": len(encoded),
        "zero_width_count": len(encoded),
        "hidden_len": len(hidden),
        "filler_count": (hidden.count(" ") if spread else 0),
        "spread": spread,
        "carrier_len": len(carrier),
        "message_len": len(message),
        "bcrypt": _bcrypt_meta(COST_KEYHASH_DEFAULT),
        "kdf_backend": bcrypt_sc.backend_name(),
        "mac_verified": True,
    }
    return EncryptResult(output=output, meta=meta)


def _repair_ciphertext(ciphertext: bytes, expected_len: int, message_key: bytes) -> tuple[bytes, int, int]:
    """Insert one missing byte anywhere and keep the candidate the tag accepts."""
    if expected_len != len(ciphertext) + 1:
        raise StegoError(
            "missing_bytes",
            f"The payload is {expected_len - len(ciphertext)} bytes short; only a single missing byte can be recovered.",
            field="text",
        )

    for offset in range(len(ciphertext) + 1):
        prefix = ciphertext[:offset]
        suffix = ciphertext[offset:]
        for value in range(256):
            candidate = prefix + bytes((value,)) + suffix
            body = candidate[:-16]
            if hmac.compare_digest(poly1305_tag(message_key, body), candidate[-16:]):
                return candidate, offset, value

    raise StegoError(
        "mac_mismatch",
        "The payload is damaged and the missing byte could not be recovered.",
        field="text",
    )


def decrypt(text: str, password: str) -> DecryptResult:
    if not isinstance(text, str) or not text:
        raise StegoError("bad_request", "Paste the text that contains the hidden payload.", field="text")
    if len(text) > MAX_REVEAL_CHARS:
        raise StegoError("too_large", "The pasted text is too long.", field="text")
    if not isinstance(password, str) or not password:
        raise StegoError("bad_request", "Enter the password used to hide the message.", field="password")

    decoded = decode_zero_width(text)
    try:
        outer = parse_outer(decoded.encoded[len(MAGIC):])
    except ProtoError as exc:
        raise StegoError("malformed", "The zero-width payload could not be parsed.", field="text") from exc

    raw_key, key_id = _derive_password_key_cached(password)

    selected: Optional[OuterEntry] = None
    for entry in outer.entries:
        if bcrypt_sc.calc_session_key_id(key_id, entry.salt, outer.cost_keyhash) == entry.keyhash:
            selected = entry
            break
    if selected is None:
        raise StegoError(
            "wrong_password",
            "That password did not unlock this message.",
            field="password",
        )

    message_key = _message_key_cached(raw_key, key_id, selected.salt)
    missing = selected.declared_len - len(selected.ciphertext)
    repaired: Optional[dict] = None
    ciphertext = selected.ciphertext

    if missing == 0:
        body = ciphertext[:-16]
        received_tag = ciphertext[-16:]
        if not hmac.compare_digest(poly1305_tag(message_key, body), received_tag):
            raise StegoError(
                "mac_mismatch",
                "The password matched, but the Poly1305 tag did not. The payload may be damaged.",
                field="text",
            )
    elif missing == 1:
        ciphertext, offset, value = _repair_ciphertext(ciphertext, selected.declared_len, message_key)
        repaired = {"offset": offset, "byte": f"{value:02x}"}
    else:
        raise StegoError(
            "missing_bytes",
            f"The payload is {missing} bytes short; only a single missing byte can be recovered.",
            field="text",
        )

    body = ciphertext[:-16]
    tag = ciphertext[-16:]
    try:
        plaintext = _decrypt_chacha(body, message_key, selected.iv)
        message, padding = parse_inner(plaintext)
    except ProtoError as exc:
        raise StegoError("malformed", "The decrypted inner message could not be parsed.", field="text") from exc

    meta = {
        "operation": "decrypt",
        "format": "zwidthbmp",
        "kdf": "SIMPLESYM",
        "key_id": f"{key_id:016x}",
        "keyhash": f"{selected.keyhash:016x}",
        "cost_keyhash": outer.cost_keyhash,
        "salt": selected.salt.hex(),
        "iv": selected.iv.hex(),
        "ciphertext_hex": ciphertext.hex(),
        "ciphertext_len": len(ciphertext),
        "ciphertext_declared_len": selected.declared_len,
        "tag_hex": tag.hex(),
        "inner_len": len(plaintext),
        "padding_hex": padding.hex(),
        "padding_len": len(padding),
        "encoded_hex": decoded.encoded.hex(),
        "encoded_len": len(decoded.encoded),
        "zero_width_count": decoded.char_count,
        "hidden_len": decoded.char_count + decoded.filler_count,
        "filler_count": decoded.filler_count,
        "outer_declared_len": outer.declared_len,
        "outer_actual_len": outer.actual_len,
        "missing": missing,
        "repaired": repaired,
        "message_len": len(message),
        "bcrypt": _bcrypt_meta(outer.cost_keyhash),
        "kdf_backend": bcrypt_sc.backend_name(),
        "mac_verified": True,
    }
    return DecryptResult(message=message, meta=meta, repaired=repaired)


# ---------------------------------------------------------------------------
# Built-in sample
# ---------------------------------------------------------------------------

def sample_text() -> str:
    hidden = encode_zero_width(SAMPLE_ENCODED)
    return f"{SAMPLE_CARRIER} {hidden}"


def sample_info() -> dict:
    return {
        "encoded_hex": SAMPLE_ENCODED_HEX,
        "encoded_len": len(SAMPLE_ENCODED),
        "carrier": SAMPLE_CARRIER,
        "password": SAMPLE_PASSWORD,
        # "note": (
        #     "The original tweet payload, with a display carrier added. One "
        #     "ciphertext byte is missing; the decoder recovers it against the "
        #     "Poly1305 tag."
        # ),
    }


def decrypt_sample(password: str = SAMPLE_PASSWORD) -> DecryptResult:
    return decrypt(sample_text(), password)

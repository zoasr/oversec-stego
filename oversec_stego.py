#!/usr/bin/env python3
"""Command-line interface for the Oversec zero-width workbench."""

from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path
from typing import Optional

import core


def _read_input(value: Optional[str], file_value: Optional[str], *, label: str) -> str:
    if file_value:
        try:
            return Path(file_value).read_text(encoding="utf-8")
        except OSError as exc:
            raise core.StegoError("bad_request", f"Could not read {label} file: {exc}") from exc
    if value is not None and value != "-":
        return value
    if sys.stdin.isatty():
        raise core.StegoError(
            "bad_request",
            f"Provide --{label} or pipe the text on stdin.",
        )
    return sys.stdin.read().rstrip("\n")


def _password(value: Optional[str], *, sample: bool = False) -> str:
    if value:
        return value
    if sample:
        return core.SAMPLE_PASSWORD
    if not sys.stdin.isatty():
        raise core.StegoError("bad_request", "Provide --password when stdin is not a terminal.")
    entered = getpass.getpass("Password: ")
    if not entered:
        raise core.StegoError("bad_request", "Password cannot be empty.", field="password")
    return entered


def _write_output(text: str, path: Optional[str], *, label: str) -> None:
    if path:
        try:
            Path(path).write_text(text, encoding="utf-8")
        except OSError as exc:
            raise core.StegoError("bad_request", f"Could not write output: {exc}") from exc
        print(f"Wrote {label} to {path}", file=sys.stderr)
    else:
        sys.stdout.write(text)
        if not text.endswith("\n"):
            sys.stdout.write("\n")


def _print_encrypt_summary(result: core.EncryptResult, path: Optional[str]) -> None:
    meta = result.meta
    print(
        "Hid {message_len} characters in {hidden_len} zero-width characters "
        "({ciphertext_len} ciphertext bytes, key id {key_id}).".format(**meta),
        file=sys.stderr,
    )
    if path is None:
        print(
            "The invisible output is on stdout. Redirect it to a file or paste it into a carrier.",
            file=sys.stderr,
        )


def cmd_encrypt(args: argparse.Namespace) -> int:
    message = _read_input(args.message, args.message_file, label="message")
    if not message:
        raise core.StegoError("bad_request", "The message is empty.", field="message")
    password = _password(args.password)
    result = core.encrypt(
        message,
        password,
        args.carrier,
        spread=args.spread,
        padding_bytes=args.padding,
    )
    if args.json:
        payload = {"output": result.output, "meta": result.meta}
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    else:
        _write_output(result.output, args.output, label="carrier")
        _print_encrypt_summary(result, args.output)
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    password = _password(args.password, sample=args.sample)
    if args.sample:
        result = core.decrypt_sample(password)
        if not args.password:
            print(f"Using the built-in sample password {core.SAMPLE_PASSWORD}.", file=sys.stderr)
    else:
        text = _read_input(args.text, args.text_file, label="text")
        result = core.decrypt(text, password)

    if args.json:
        payload = {
            "message": result.message,
            "repaired": result.repaired,
            "meta": result.meta,
        }
        sys.stdout.write(json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    else:
        _write_output(result.message, args.output, label="message")
        if result.repaired:
            print(
                "Recovered a missing byte at ciphertext offset {offset} (0x{byte}).".format(
                    **result.repaired
                ),
                file=sys.stderr,
            )
        print(
            "Poly1305 tag verified. Key id {key_id}.".format(**result.meta),
            file=sys.stderr,
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="oversec_stego.py",
        description=(
            "Hide and reveal Oversec zwidthbmp + SIMPLESYM text. "
            "This is a compatible reimplementation, not an official Oversec tool."
        ),
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0.0")
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="hide a message in zero-width characters")
    enc.add_argument("-m", "--message", help="the text to hide; use - for stdin")
    enc.add_argument("--message-file", help="read the message from a UTF-8 file")
    enc.add_argument("-p", "--password", help="password; prompted when omitted")
    enc.add_argument(
        "-c",
        "--carrier",
        default=core.DEFAULT_CARRIER,
        help="visible text the invisible payload rides in",
    )
    enc.add_argument(
        "--spread",
        type=int,
        default=0,
        help="insert one filler space after this many hidden characters (0 disables)",
    )
    enc.add_argument(
        "--padding",
        type=int,
        default=6,
        help="random inner padding bytes (default: 6)",
    )
    enc.add_argument("-o", "--output", help="write the carrier to a UTF-8 file")
    enc.add_argument("--json", action="store_true", help="print JSON with metadata")
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="reveal a message from zero-width characters")
    dec.add_argument("-t", "--text", help="text containing the payload; use - for stdin")
    dec.add_argument("--text-file", help="read the text from a UTF-8 file")
    dec.add_argument("-p", "--password", help="password; prompted when omitted")
    dec.add_argument("--sample", action="store_true", help="decrypt the built-in tweet sample")
    dec.add_argument("-o", "--output", help="write the revealed message to a UTF-8 file")
    dec.add_argument("--json", action="store_true", help="print JSON with metadata")
    dec.set_defaults(func=cmd_decrypt)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except core.StegoError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Cancelled.", file=sys.stderr)
        return 130
    except Exception as exc:  # pragma: no cover - last-resort CLI guard
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

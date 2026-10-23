#!/usr/bin/env python3
"""Local HTTP server for the Zero Width workbench."""

from __future__ import annotations

import argparse
import json
import mimetypes
import sys
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional

import core

ROOT = Path(__file__).resolve().parent
MAX_BODY_BYTES = 512 * 1024

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/fonts.css": ("fonts.css", "text/css; charset=utf-8"),
    "/tokens.css": ("tokens.css", "text/css; charset=utf-8"),
    "/base.css": ("base.css", "text/css; charset=utf-8"),
    "/favicon.svg": ("favicon.svg", "image/svg+xml"),
    "/fonts/familjen-grotesk-latin.woff2": (
        "fonts/familjen-grotesk-latin.woff2",
        "font/woff2",
    ),
    "/fonts/ibm-plex-sans-latin.woff2": (
        "fonts/ibm-plex-sans-latin.woff2",
        "font/woff2",
    ),
    "/fonts/jetbrains-mono-latin.woff2": (
        "fonts/jetbrains-mono-latin.woff2",
        "font/woff2",
    ),
}

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'; "
        "frame-ancestors 'none'"
    ),
}


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, field: Optional[str] = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.field = field


class Handler(BaseHTTPRequestHandler):
    server_version = "ZeroWidth/1.0"
    protocol_version = "HTTP/1.1"

    # -- response helpers -------------------------------------------------

    def _send_headers(
        self,
        status: int,
        content_type: str,
        content_length: int,
        *,
        cache: str = "no-store",
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Cache-Control", cache)
        for key, value in SECURITY_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()

    def _send_json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self._send_headers(status, "application/json; charset=utf-8", len(body))
        self.wfile.write(body)

    def _send_error_json(
        self,
        status: int,
        code: str,
        message: str,
        field: Optional[str] = None,
    ) -> None:
        error: dict[str, Any] = {"code": code, "message": message}
        if field:
            error["field"] = field
        self._send_json(status, {"ok": False, "error": error})

    def _send_static(self, path: str, *, include_body: bool = True) -> None:
        entry = STATIC_FILES.get(path)
        if entry is None:
            self._send_error_json(HTTPStatus.NOT_FOUND, "not_found", "Not found.")
            return
        filename, content_type = entry
        file_path = ROOT / filename
        if not file_path.is_file():
            self._send_error_json(HTTPStatus.NOT_FOUND, "not_found", "Not found.")
            return
        data = file_path.read_bytes()
        self._send_headers(
            HTTPStatus.OK,
            content_type,
            len(data),
            cache="no-cache" if content_type.startswith("text/") else "public, max-age=3600",
        )
        if include_body:
            self.wfile.write(data)

    # -- request parsing --------------------------------------------------

    def _read_json(self) -> dict[str, Any]:
        length_header = self.headers.get("Content-Length")
        if not length_header:
            raise ApiError(HTTPStatus.LENGTH_REQUIRED, "bad_request", "Content-Length is required.")
        try:
            length = int(length_header)
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "bad_request", "Invalid Content-Length.") from exc
        if length <= 0:
            raise ApiError(HTTPStatus.BAD_REQUEST, "bad_request", "Request body is empty.")
        if length > MAX_BODY_BYTES:
            raise ApiError(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "too_large", "Request body is too large.")
        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "bad_request", "Request body must be UTF-8 JSON.") from exc
        if not isinstance(payload, dict):
            raise ApiError(HTTPStatus.BAD_REQUEST, "bad_request", "Request body must be a JSON object.")
        return payload

    @staticmethod
    def _require_string(payload: dict[str, Any], key: str, *, default: Optional[str] = None) -> str:
        value = payload.get(key, default)
        if not isinstance(value, str):
            raise ApiError(HTTPStatus.BAD_REQUEST, "bad_request", f"{key} must be a string.", key)
        return value

    @staticmethod
    def _optional_int(payload: dict[str, Any], key: str, default: int, minimum: int, maximum: int) -> int:
        value = payload.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int):
            raise ApiError(HTTPStatus.BAD_REQUEST, "bad_request", f"{key} must be an integer.", key)
        if not (minimum <= value <= maximum):
            raise ApiError(
                HTTPStatus.BAD_REQUEST,
                "bad_request",
                f"{key} must be between {minimum} and {maximum}.",
                key,
            )
        return value

    # -- API handlers -----------------------------------------------------

    def _handle_health(self) -> None:
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "version": "1.0.0",
                "native_bcrypt": core.bcrypt_sc.native_available(),
                "kdf_backend": core.bcrypt_sc.backend_name(),
            },
        )

    def _handle_sample(self) -> None:
        self._send_json(HTTPStatus.OK, {"ok": True, **core.sample_info()})

    def _handle_encrypt(self) -> None:
        payload = self._read_json()
        message = self._require_string(payload, "message")
        password = self._require_string(payload, "password")
        carrier = self._require_string(payload, "carrier", default=core.DEFAULT_CARRIER)
        spread = self._optional_int(payload, "spread", 0, 0, 10_000)
        padding = self._optional_int(payload, "padding", 6, 0, 255)

        if len(message) > 5_000:
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "too_large", "The message is too long.", "message")
        if len(password) > 512:
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "too_large", "The password is too long.", "password")
        if len(carrier) > 5_000:
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "too_large", "The carrier is too long.", "carrier")

        try:
            result = core.encrypt(
                message,
                password,
                carrier,
                spread=spread,
                padding_bytes=padding,
            )
        except core.StegoError as exc:
            status = HTTPStatus.BAD_REQUEST if exc.code in {"bad_request", "too_large"} else HTTPStatus.UNPROCESSABLE_ENTITY
            raise ApiError(status, exc.code, exc.message, exc.field) from exc

        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "output": result.output,
                "meta": result.meta,
            },
        )

    def _handle_decrypt(self) -> None:
        payload = self._read_json()
        text = self._require_string(payload, "text")
        password = self._require_string(payload, "password")
        if len(text) > 200_000:
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "too_large", "The pasted text is too long.", "text")
        if len(password) > 512:
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "too_large", "The password is too long.", "password")

        try:
            result = core.decrypt(text, password)
        except core.StegoError as exc:
            status = HTTPStatus.BAD_REQUEST if exc.code in {"bad_request", "too_large"} else HTTPStatus.UNPROCESSABLE_ENTITY
            raise ApiError(status, exc.code, exc.message, exc.field) from exc

        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "message": result.message,
                "repaired": result.repaired,
                "meta": result.meta,
            },
        )

    # -- HTTP methods -----------------------------------------------------

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            if path == "/api/health":
                self._handle_health()
            elif path == "/api/sample":
                self._handle_sample()
            elif path in STATIC_FILES:
                self._send_static(path)
            else:
                self._send_error_json(HTTPStatus.NOT_FOUND, "not_found", "Not found.")
        except Exception as exc:  # pragma: no cover - last-resort server guard
            self.log_error("GET %s failed: %s", path, exc)
            self._send_error_json(HTTPStatus.INTERNAL_SERVER_ERROR, "internal", "The server hit an unexpected error.")

    def do_HEAD(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in STATIC_FILES:
            self._send_static(path, include_body=False)
        else:
            self._send_headers(HTTPStatus.NOT_FOUND, "application/json; charset=utf-8", 0)

    def do_POST(self) -> None:
        path = self.path.split("?", 1)[0]
        try:
            if path == "/api/encrypt":
                self._handle_encrypt()
            elif path == "/api/decrypt":
                self._handle_decrypt()
            else:
                self._send_error_json(HTTPStatus.NOT_FOUND, "not_found", "Not found.")
        except ApiError as exc:
            self._send_error_json(exc.status, exc.code, exc.message, exc.field)
        except core.StegoError as exc:
            self._send_error_json(HTTPStatus.UNPROCESSABLE_ENTITY, exc.code, exc.message, exc.field)
        except Exception as exc:  # pragma: no cover - last-resort server guard
            self.log_error("POST %s failed: %s", path, exc)
            self._send_error_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal",
                "The server hit an unexpected error.",
            )

    def do_OPTIONS(self) -> None:
        self._send_error_json(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed", "Method not allowed.")

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(
            "%s - - [%s] %s\n"
            % (self.address_string(), self.log_date_time_string(), fmt % args)
        )


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _loopback(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def run(host: str = "127.0.0.1", port: int = 8765, open_browser: bool = False) -> None:
    if not _loopback(host):
        print(
            "Warning: this server has no authentication. Bind it to a loopback address unless you know what you are doing.",
            file=sys.stderr,
        )
    httpd = Server((host, port), Handler)
    actual_port = httpd.server_address[1]
    url = f"http://{host}:{actual_port}/"
    print(f"Zero Width is running at {url}", file=sys.stderr)
    print("Press Ctrl+C to stop.", file=sys.stderr)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping.", file=sys.stderr)
    finally:
        httpd.server_close()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local Zero Width workbench.")
    parser.add_argument("--host", default="127.0.0.1", help="bind address (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="port (default: 8765; 0 picks a free port)")
    parser.add_argument("--open", action="store_true", help="open the app in the default browser")
    args = parser.parse_args(argv)
    run(args.host, args.port, args.open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Tests for the local HTTP API and static allowlist."""

from __future__ import annotations

import json
import threading
import unittest
import urllib.error
import urllib.request

import core
import server


class QuietHandler(server.Handler):
    def log_message(self, fmt: str, *args: object) -> None:
        pass


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.httpd = server.Server(("127.0.0.1", 0), QuietHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)

    def request(self, method: str, path: str, payload: dict | None = None) -> tuple[int, dict, bytes]:
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            self.base + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.status, dict(response.headers), response.read()
        except urllib.error.HTTPError as error:
            try:
                return error.code, dict(error.headers), error.read()
            finally:
                error.close()

    def post(self, path: str, payload: dict) -> tuple[int, dict]:
        status, _headers, body = self.request("POST", path, payload)
        return status, json.loads(body.decode("utf-8"))

    def test_health(self) -> None:
        status, headers, body = self.request("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(headers["X-Frame-Options"], "DENY")
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data["ok"])
        self.assertIsInstance(data["native_bcrypt"], bool)
        self.assertIn(data["kdf_backend"], {"native", "python"})

    def test_sample_endpoint(self) -> None:
        status, _headers, body = self.request("GET", "/api/sample")
        self.assertEqual(status, 200)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data["ok"])
        self.assertEqual(data["password"], core.SAMPLE_PASSWORD)
        self.assertEqual(data["carrier"], core.SAMPLE_CARRIER)
        self.assertEqual(data["encoded_len"], 118)
        self.assertEqual(len(data["encoded_hex"]), 236)
        self.assertIn("ciphertext byte", data["note"])

    def test_static_index_and_assets(self) -> None:
        status, headers, body = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", headers["Content-Type"])
        self.assertIn(b"Zero Width", body)
        self.assertIn("Content-Security-Policy", headers)
        csp = headers["Content-Security-Policy"]
        self.assertIn("font-src 'self'", csp)
        self.assertNotIn("fonts.googleapis.com", csp)
        self.assertNotIn("fonts.gstatic.com", csp)
        self.assertNotIn(b"fonts.googleapis.com", body)
        self.assertNotIn(b"fonts.gstatic.com", body)
        for path, content_type in [
            ("/styles.css", "text/css"),
            ("/app.js", "text/javascript"),
            ("/fonts.css", "text/css"),
            ("/tokens.css", "text/css"),
            ("/base.css", "text/css"),
            ("/favicon.svg", "image/svg+xml"),
            ("/fonts/familjen-grotesk-latin.woff2", "font/woff2"),
            ("/fonts/ibm-plex-sans-latin.woff2", "font/woff2"),
            ("/fonts/jetbrains-mono-latin.woff2", "font/woff2"),
        ]:
            status, headers, body = self.request("GET", path)
            self.assertEqual(status, 200, path)
            self.assertIn(content_type, headers["Content-Type"], path)
            self.assertTrue(body, path)

    def test_static_allowlist_rejects_other_paths(self) -> None:
        for path in ["/core.py", "/server.py", "/../core.py", "/tests/test_core.py"]:
            status, _headers, _body = self.request("GET", path)
            self.assertEqual(status, 404, path)

    def test_head_request_has_no_body(self) -> None:
        status, headers, body = self.request("HEAD", "/")
        self.assertEqual(status, 200)
        self.assertGreater(int(headers["Content-Length"]), 0)
        self.assertEqual(body, b"")

    def test_encrypt_decrypt_round_trip(self) -> None:
        status, encrypted = self.post(
            "/api/encrypt",
            {
                "message": "API round trip",
                "password": "api password",
                "carrier": "An ordinary post.",
                "spread": 0,
                "padding": 3,
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(encrypted["ok"])
        self.assertTrue(encrypted["output"].startswith("An ordinary post. "))
        self.assertEqual(encrypted["meta"]["operation"], "encrypt")
        self.assertEqual(encrypted["meta"]["padding_len"], 3)

        status, decrypted = self.post(
            "/api/decrypt",
            {"text": encrypted["output"], "password": "api password"},
        )
        self.assertEqual(status, 200)
        self.assertTrue(decrypted["ok"])
        self.assertEqual(decrypted["message"], "API round trip")
        self.assertIsNone(decrypted["repaired"])
        self.assertTrue(decrypted["meta"]["mac_verified"])

    def test_sample_decrypts_through_api(self) -> None:
        status, decrypted = self.post(
            "/api/decrypt",
            {"text": core.sample_text(), "password": core.SAMPLE_PASSWORD},
        )
        self.assertEqual(status, 200)
        self.assertEqual(decrypted["message"], "i love you" * 4)
        self.assertEqual(decrypted["repaired"], {"offset": 16, "byte": "0f"})
        self.assertTrue(decrypted["meta"]["mac_verified"])

    def test_wrong_password_error_shape(self) -> None:
        status, error = self.post(
            "/api/decrypt",
            {"text": core.sample_text(), "password": "wrong"},
        )
        self.assertEqual(status, 422)
        self.assertFalse(error["ok"])
        self.assertEqual(error["error"]["code"], "wrong_password")
        self.assertEqual(error["error"]["field"], "password")

    def test_no_payload_error_shape(self) -> None:
        status, error = self.post(
            "/api/decrypt",
            {"text": "Just a plain sentence.", "password": "password"},
        )
        self.assertEqual(status, 422)
        self.assertFalse(error["ok"])
        self.assertEqual(error["error"]["code"], "no_payload")
        self.assertEqual(error["error"]["field"], "text")

    def test_unknown_api_is_404(self) -> None:
        status, error = self.post("/api/unknown", {})
        self.assertEqual(status, 404)
        self.assertEqual(error["error"]["code"], "not_found")

    def test_invalid_json_is_400(self) -> None:
        request = urllib.request.Request(
            self.base + "/api/encrypt",
            data=b"{not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                self.fail(f"expected an error, got {response.status}")
        except urllib.error.HTTPError as error:
            try:
                self.assertEqual(error.code, 400)
                data = json.loads(error.read().decode("utf-8"))
                self.assertEqual(data["error"]["code"], "bad_request")
            finally:
                error.close()


if __name__ == "__main__":
    unittest.main()

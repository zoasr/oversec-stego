"""Tests for the shared Oversec crypto core."""

from __future__ import annotations

import unittest

import bcrypt_sc
import core


SAMPLE_SALT = bytes.fromhex("90b7e8f790100eb6e0ad014080d9125a")
SAMPLE_RAW_KEY = bytes.fromhex(
    "90e07943b0b36c248a7892efda7c1a61adaca38e452b3f479c2633595847f0ef"
)
SAMPLE_MESSAGE_KEY = bytes.fromhex(
    "622f1ed04a4e4d5d04b979f6796d85de622f1ed04a4e4d5d04b979f6796d85de"
)
RESTORED_CIPHERTEXT = bytes.fromhex(
    "0a67c889f1a92b58a6cdce75b16f67970f83abb8dc124223c78625c10b5ee556"
    "7b9507b6dca515e3c64d1b858fe9a289b3aa6c5c3816bf6c96b3ffdeb604fbaf"
    "0664e371"
)


class BcryptCompatibilityTests(unittest.TestCase):
    def test_sample_password_derivation(self) -> None:
        raw_key, key_id = bcrypt_sc.derive_password_key(core.SAMPLE_PASSWORD)
        self.assertEqual(raw_key, SAMPLE_RAW_KEY)
        self.assertEqual(format(key_id, "016x"), "a1e518fa50a0f4af")

    def test_sample_session_keyhash(self) -> None:
        _, key_id = bcrypt_sc.derive_password_key(core.SAMPLE_PASSWORD)
        keyhash = bcrypt_sc.calc_session_key_id(key_id, SAMPLE_SALT, 5)
        self.assertEqual(format(keyhash, "016x"), "6c853ff546a3e13c")

    def test_sample_message_key_repeats_first_half(self) -> None:
        raw_key, _ = bcrypt_sc.derive_password_key(core.SAMPLE_PASSWORD)
        message_key = bcrypt_sc.get_encryption_key(raw_key, SAMPLE_SALT)
        self.assertEqual(message_key, SAMPLE_MESSAGE_KEY)
        self.assertEqual(message_key[:16], message_key[16:])

    def test_native_helper_matches_pure_python(self) -> None:
        if not bcrypt_sc.native_available():
            self.skipTest("native bcrypt helper is not available")
        password = b"correct horse battery staple"
        salt = bytes.fromhex("00112233445566778899aabbccddeeff")
        native = bcrypt_sc._native_bcrypt_raw(password, salt, 4)
        pure = bcrypt_sc._pure_bcrypt_raw(password, salt, 4)
        self.assertEqual(native, pure)
        self.assertEqual(len(native), 24)

    def test_brcryptify_output_length(self) -> None:
        raw = bcrypt_sc.brcryptify_password(
            core.SAMPLE_PASSWORD,
            bcrypt_sc.FIXED_PASSWORD_SALT,
            core.PASSWORD_COST,
            32,
        )
        self.assertEqual(raw, SAMPLE_RAW_KEY)
        self.assertEqual(len(raw), 32)


class ZeroWidthTests(unittest.TestCase):
    def test_mapping_boundaries(self) -> None:
        self.assertEqual(core.byte_to_zero_width(0x00), "\ufe00")
        self.assertEqual(core.byte_to_zero_width(0x0F), "\ufe0f")
        self.assertEqual(core.byte_to_zero_width(0x10), "\U000e0100")
        self.assertEqual(core.byte_to_zero_width(0xFF), "\U000e01ef")
        self.assertEqual(core.zero_width_to_byte("\ufe00"), 0x00)
        self.assertEqual(core.zero_width_to_byte("\ufe0f"), 0x0F)
        self.assertEqual(core.zero_width_to_byte("\U000e0100"), 0x10)
        self.assertEqual(core.zero_width_to_byte("\U000e01ef"), 0xFF)
        self.assertIsNone(core.zero_width_to_byte("A"))

    def test_all_byte_values_round_trip(self) -> None:
        data = bytes(range(256))
        encoded = core.encode_zero_width(data)
        self.assertEqual(len(encoded), 256)
        decoded = core.decode_zero_width(core.MAGIC_ZERO_WIDTH + encoded)
        self.assertEqual(decoded.encoded, core.MAGIC + data)
        self.assertEqual(decoded.char_count, 259)
        self.assertEqual(decoded.filler_count, 0)

    def test_spread_fillers_are_ignored(self) -> None:
        data = b"\x01" * 62
        encoded = core.encode_zero_width(data, spread=30)
        self.assertEqual(encoded.count(" "), 2)
        decoded = core.decode_zero_width(core.MAGIC_ZERO_WIDTH + encoded)
        self.assertEqual(decoded.encoded, core.MAGIC + data)
        self.assertEqual(decoded.char_count, 65)
        self.assertEqual(decoded.filler_count, 2)

    def test_missing_magic_is_an_error(self) -> None:
        with self.assertRaises(core.StegoError) as raised:
            core.decode_zero_width("No invisible payload here.")
        self.assertEqual(raised.exception.code, "no_payload")
        self.assertEqual(raised.exception.field, "text")


class ProtobufTests(unittest.TestCase):
    def test_inner_round_trip(self) -> None:
        text = "hello, 世界"
        padding = b"\x00\x01\xff"
        inner = core.build_inner(text, padding)
        parsed_text, parsed_padding = core.parse_inner(inner)
        self.assertEqual(parsed_text, text)
        self.assertEqual(parsed_padding, padding)

    def test_outer_round_trip(self) -> None:
        keyhash = 0x1122334455667788
        salt = bytes(range(16))
        iv = bytes(range(8))
        ciphertext = bytes(range(68))
        outer = core.build_outer(5, keyhash, salt, iv, ciphertext)
        encoded = core._encode_varint(len(outer)) + outer
        parsed = core.parse_outer(encoded)
        self.assertEqual(parsed.cost_keyhash, 5)
        self.assertEqual(parsed.declared_len, len(outer))
        self.assertEqual(parsed.actual_len, len(outer))
        self.assertEqual(len(parsed.entries), 1)
        entry = parsed.entries[0]
        self.assertEqual(entry.keyhash, keyhash)
        self.assertEqual(entry.salt, salt)
        self.assertEqual(entry.iv, iv)
        self.assertEqual(entry.ciphertext, ciphertext)
        self.assertEqual(entry.declared_len, 68)
        self.assertFalse(entry.truncated)

    def test_sample_outer_is_one_byte_short(self) -> None:
        parsed = core.parse_outer(core.SAMPLE_ENCODED[3:])
        self.assertEqual(parsed.declared_len, 115)
        self.assertEqual(parsed.actual_len, 114)
        entry = parsed.entries[0]
        self.assertEqual(entry.declared_len, 68)
        self.assertEqual(len(entry.ciphertext), 67)
        self.assertTrue(entry.truncated)


class RepairTests(unittest.TestCase):
    def test_poly1305_matches_restored_sample(self) -> None:
        tag = core.poly1305_tag(SAMPLE_MESSAGE_KEY, RESTORED_CIPHERTEXT[:-16])
        self.assertEqual(tag, RESTORED_CIPHERTEXT[-16:])

    def test_one_missing_ciphertext_byte_is_recovered(self) -> None:
        short = RESTORED_CIPHERTEXT[:16] + RESTORED_CIPHERTEXT[17:]
        repaired, offset, value = core._repair_ciphertext(
            short, len(RESTORED_CIPHERTEXT), SAMPLE_MESSAGE_KEY
        )
        self.assertEqual(repaired, RESTORED_CIPHERTEXT)
        self.assertEqual(offset, 16)
        self.assertEqual(value, 0x0F)

    def test_two_missing_ciphertext_bytes_are_rejected(self) -> None:
        short = RESTORED_CIPHERTEXT[:16] + RESTORED_CIPHERTEXT[18:]
        with self.assertRaises(core.StegoError) as raised:
            core._repair_ciphertext(
                short, len(RESTORED_CIPHERTEXT), SAMPLE_MESSAGE_KEY
            )
        self.assertEqual(raised.exception.code, "missing_bytes")


class SampleTests(unittest.TestCase):
    def test_sample_has_the_expected_zero_width_count(self) -> None:
        text = core.sample_text()
        count = sum(1 for char in text if core.zero_width_to_byte(char) is not None)
        self.assertEqual(count, 118)

    def test_sample_decrypts_and_repairs(self) -> None:
        result = core.decrypt_sample()
        self.assertEqual(result.message, "i love you" * 4)
        self.assertEqual(result.repaired, {"offset": 16, "byte": "0f"})
        self.assertTrue(result.meta["mac_verified"])
        self.assertEqual(result.meta["ciphertext_len"], 68)
        self.assertEqual(result.meta["missing"], 1)
        self.assertEqual(result.meta["padding_hex"], "c8ba93301e64")

    def test_sample_decrypts_with_surrounding_text(self) -> None:
        result = core.decrypt(f"prefix {core.sample_text()} suffix", core.SAMPLE_PASSWORD)
        self.assertEqual(result.message, "i love you" * 4)

    def test_sample_wrong_password(self) -> None:
        with self.assertRaises(core.StegoError) as raised:
            core.decrypt(core.sample_text(), "not the password")
        self.assertEqual(raised.exception.code, "wrong_password")
        self.assertEqual(raised.exception.field, "password")

    def test_sample_with_two_missing_bytes_fails(self) -> None:
        text = core.sample_text()
        positions = [
            index
            for index, char in enumerate(text)
            if core.zero_width_to_byte(char) is not None
        ]
        # Keep the three magic characters intact and remove two payload bytes.
        broken = (
            text[: positions[3]]
            + text[positions[3] + 1 : positions[4]]
            + text[positions[4] + 1 :]
        )
        with self.assertRaises(core.StegoError) as raised:
            core.decrypt(broken, core.SAMPLE_PASSWORD)
        self.assertIn(
            raised.exception.code,
            {"missing_bytes", "mac_mismatch", "malformed"},
        )


class RoundTripTests(unittest.TestCase):
    def test_round_trip_without_spread(self) -> None:
        message = "Meet me at the old pier at midnight."
        password = "correct horse battery staple"
        carrier = "A completely ordinary post."
        result = core.encrypt(
            message,
            password,
            carrier,
            spread=0,
            padding_bytes=4,
        )
        self.assertTrue(result.output.startswith(carrier + " "))
        self.assertEqual(result.meta["operation"], "encrypt")
        self.assertEqual(result.meta["encoded_len"], len(core.decode_zero_width(result.output).encoded))
        decrypted = core.decrypt(result.output, password)
        self.assertEqual(decrypted.message, message)
        self.assertIsNone(decrypted.repaired)
        self.assertTrue(decrypted.meta["mac_verified"])

    def test_round_trip_with_spread(self) -> None:
        message = "The quick brown fox jumps over the lazy dog."
        password = "another password"
        result = core.encrypt(
            message,
            password,
            "Nothing to see here.",
            spread=30,
            padding_bytes=0,
        )
        self.assertGreater(result.meta["filler_count"], 0)
        decrypted = core.decrypt(result.output, password)
        self.assertEqual(decrypted.message, message)
        self.assertGreater(decrypted.meta["filler_count"], 0)
        self.assertTrue(decrypted.meta["mac_verified"])

    def test_empty_message_is_rejected(self) -> None:
        with self.assertRaises(core.StegoError) as raised:
            core.encrypt("", "password")
        self.assertEqual(raised.exception.code, "bad_request")
        self.assertEqual(raised.exception.field, "message")

    def test_empty_password_is_rejected(self) -> None:
        with self.assertRaises(core.StegoError) as raised:
            core.encrypt("message", "")
        self.assertEqual(raised.exception.code, "bad_request")
        self.assertEqual(raised.exception.field, "password")

    def test_plain_text_is_not_a_payload(self) -> None:
        with self.assertRaises(core.StegoError) as raised:
            core.decrypt("This is just a sentence.", "password")
        self.assertEqual(raised.exception.code, "no_payload")
        self.assertEqual(raised.exception.field, "text")


if __name__ == "__main__":
    unittest.main()

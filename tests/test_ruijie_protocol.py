from __future__ import annotations

import hashlib
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from campus_net_assistant import ruijie_protocol as protocol
from campus_net_assistant.whirlpool import whirlpool_digest
from tests.test_native_wired import workspace_temp


LOCAL = bytes.fromhex("001122334455")
SERVER = bytes.fromhex("66778899aabb")


def tlv_extension() -> bytes:
    output = bytearray(576)
    cursor = 0x46
    for item_type, length in (
        (0x17, 34),
        (0x18, 6),
        (0x2D, 8),
        (0x2F, 18),
        (0x36, 18),
        (0x38, 18),
        (0x4E, 18),
        (0x4D, 130),
        (0x54, 66),
        (0x76, 16),
    ):
        output[cursor:cursor + 2] = b"\x1a" + bytes([length + 6])
        base = cursor + 2
        output[base:base + 4] = b"\x00\x00\x13\x11"
        output[base + 4] = item_type
        output[base + 5] = length
        cursor = base + 4 + length
    return bytes(output)


def ethernet(packet_type: int, source: bytes, destination: bytes, body: bytes, trailer: bytes = b"") -> bytes:
    return destination + source + b"\x88\x8e\x01" + bytes([packet_type]) + struct.pack("!H", len(body)) + body + trailer


def pcapng(frames: list[bytes]) -> bytes:
    def block(kind: int, body: bytes) -> bytes:
        body += b"\0" * ((-len(body)) % 4)
        length = 12 + len(body)
        return struct.pack("<II", kind, length) + body + struct.pack("<I", length)
    section = block(0x0A0D0D0A, b"\x4d\x3c\x2b\x1a" + struct.pack("<HHq", 1, 0, -1))
    interface = block(1, struct.pack("<HHI", 1, 0, 65535))
    packets = []
    for index, frame in enumerate(frames, 1):
        packets.append(block(6, struct.pack("<IIIII", 0, 0, index, len(frame), len(frame)) + frame))
    return section + interface + b"".join(packets)


def fake_pe(code: bytes) -> bytes:
    data = bytearray(0x200 + len(code))
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    section = 0x80 + 24 + 0xF0
    data[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<II", data, section + 16, len(code), 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200:] = code
    return bytes(data)


class RuijieProtocolTests(unittest.TestCase):
    def setUp(self):
        self.folder = workspace_temp(self)

    def test_builtin_njmu_profile_is_exact_version_bound_and_redacted(self):
        from campus_net_assistant.ruijie_profiles import builtin_profile_for_client

        supported_hash = "b84d7d794a94eb3679caf826b8fddfec76cdc028a1c0e95ae7fcf61e37927bfe"
        profile = builtin_profile_for_client(supported_hash)
        self.assertIsNotNone(profile)
        self.assertEqual(profile.client_sha256, supported_hash)
        self.assertEqual(len(profile.extension), 576)
        self.assertEqual(len(profile.echo_body), 27)
        self.assertEqual(profile.capture_hashes, ())
        for property_type in (0x17, 0x18, 0x2D, 0x2F, 0x36, 0x38, 0x4E, 0x4D, 0x54, 0x76):
            self.assertFalse(any(protocol.get_property(profile.extension, property_type)))
        self.assertIsNone(builtin_profile_for_client("0" * 64))

    def test_extracts_only_successful_md5_template_and_echo(self):
        identity = b"test-user"
        extension = bytearray(tlv_extension())
        extension[:0x17] = bytes(range(0x17))
        extension = protocol.set_property(bytes(extension), 0x2D, LOCAL)
        password_hash = bytes.fromhex("102132435465768798a9bacbdcedfe0f")
        extension = protocol.set_property(extension, 0x2F, password_hash)
        extension = protocol.set_property(extension, 0x4D, identity)
        extension = protocol.set_property(extension, 0x36, bytes(range(16)))
        extension = protocol.set_property(extension, 0x38, bytes(range(16, 32)))
        extension = protocol.set_property(extension, 0x4E, bytes(range(32, 48)))
        extension = protocol.set_property(extension, 0x54, b"captured-disk-serial")
        extension = protocol.set_property(extension, 0x76, b"198.51.100.53")
        md5 = b"\x02\x09" + struct.pack("!H", 6 + 16 + len(identity)) + b"\x04\x10" + b"x" * 16 + identity
        success = b"\x03\x09\x00\x04"
        echo = bytes(range(27))
        capture = self.folder / "success.pcapng"
        capture.write_bytes(pcapng([
            ethernet(0, LOCAL, SERVER, md5, extension),
            ethernet(0, SERVER, LOCAL, success),
            ethernet(0xBF, LOCAL, SERVER, echo),
        ]))
        client = self.folder / "8021x.exe"
        client.write_bytes(b"official-client")
        profile = protocol.extract_compatibility_profile([capture], client)
        self.assertEqual(profile.extension[:0x17], bytes(0x17))
        self.assertEqual(protocol.get_property(profile.extension, 0x2D), bytes(6))
        self.assertEqual(protocol.get_property(profile.extension, 0x2F), bytes(16))
        self.assertEqual(protocol.get_property(profile.extension, 0x4D), bytes(128))
        for property_type in (0x36, 0x38, 0x4E, 0x54, 0x76):
            self.assertFalse(any(protocol.get_property(profile.extension, property_type)))
        self.assertNotIn(identity, profile.extension)
        self.assertNotIn(password_hash, profile.extension)
        self.assertEqual(profile.echo_body[6:10], bytes(4))
        self.assertEqual(profile.echo_body[16:20], bytes(4))
        serialized = protocol.profile_json(profile)
        self.assertNotIn("test-user", serialized)
        self.assertNotIn(LOCAL.hex(), serialized)
        self.assertNotIn(password_hash.hex(), serialized)
        self.assertEqual(protocol.load_profile(serialized), profile)

    def test_capture_without_success_is_rejected(self):
        extension = tlv_extension()
        body = b"\x02\x01\x00\x16\x04\x10" + b"x" * 16
        capture = self.folder / "failed.pcapng"
        capture.write_bytes(pcapng([ethernet(0, LOCAL, SERVER, body, extension)]))
        client = self.folder / "8021x.exe"
        client.write_bytes(b"client")
        with self.assertRaises(protocol.RuijieProtocolError):
            protocol.extract_compatibility_profile([capture], client)

    def test_md5_response_uses_identifier_password_and_challenge(self):
        challenge = bytes(range(16))
        expected = hashlib.md5(b"\x07secret" + challenge).digest()
        self.assertEqual(protocol.md5_response(7, "secret", challenge), expected)

    def test_whirlpool_matches_iso_vectors(self):
        expected_empty = (
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7"
            "3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
        )
        expected_quick = (
            "b97de512e91e3828b40d2b0fdce9ceb3c4a71f9bea8d88e75c4fa854df36725f"
            "d2b52eb6544edcacd6f8beddfea403cb55ae31f03ad62a5ef54e42ee82c3fb35"
        )
        self.assertEqual(whirlpool_digest(b"").hex(), expected_empty)
        self.assertEqual(whirlpool_digest(b"The quick brown fox jumps over the lazy dog").hex(), expected_quick)

    def test_v4_branch1_is_challenge_bound_and_other_branches_fail_closed(self):
        first = bytes([0, 0, 0, 1]) + bytes(range(4, 16))
        second = bytes([0, 0, 0, 6]) + bytes(range(4, 16))
        self.assertEqual(protocol.v4_check_type(first), 1)
        self.assertEqual(len(protocol.public_v4_branch1_reference(first)), 128)
        self.assertNotEqual(
            protocol.public_v4_branch1_reference(first),
            protocol.public_v4_branch1_reference(second),
        )
        with self.assertRaises(protocol.RuijieProtocolError):
            protocol.public_v4_branch1_reference(bytes(16))

    def test_v4_branch_selection_matches_unsigned_c_remainder(self):
        challenge = bytes([0x80, 0, 0, 0x80]) + bytes(12)
        self.assertEqual(protocol.v4_check_type(challenge), ((-128 - 128) & 0xFFFFFFFF) % 5)

    def test_all_public_v4_branches_match_reference_vectors(self):
        expected = (
            "b464896d8135ee1da7dd2926bcbb65ae4eb77df681012a8e52ce8bf566125194"
            "ed197bcfda8f729f582a1d330d5f03ba48245a8325f1215ebbe4cf9c1ca25b0b",
            "1eabe9c274670719ba61eb520d304576dd4cfff1e1f22a2feaeed4cbbf2aa274"
            "093e1a5067c44a9452416a6e71f1aa7d186ffd9df22deccfafb8a7602ae21a82",
            "07d6a51a57016c9bfc56bc18abb56ef2e2db6a8e8500ec47de42c2c5fbaac612"
            "f082ffd5d575fc0f0c27dd3f5c4eec27f0688a4a21e7ca440f02f753aac7c0be",
            "35cd325505175711faadb84e24efc41d43c8ae8196a79018aafa0addbb93d884"
            "7c68479b88cacb8b923ac6639f09b9cce4b24ce41bf0fca2fc0803fcdc139370",
            "4321ded45fc18a6689764fc71c8fba469f811e1c29371192e32c8fc0d5cbc598"
            "6618706453608297b8ff3fb7fd67ef719373c33cbc50b812d4e76f266cc964a2",
        )
        for branch, value in enumerate(expected):
            challenge = bytes([branch]) + bytes(15)
            self.assertEqual(protocol.v4_check_type(challenge), branch)
            self.assertEqual(protocol.public_v4_reference(challenge), value.encode("ascii"))

    def test_password_property_uses_encoded_bytes_and_sixteen_byte_password_block(self):
        challenge = bytes(range(16))
        digest = hashlib.md5(b"person" + challenge).digest()
        expected = bytes(left ^ right for left, right in zip(digest, b"secret".ljust(16, b"\0")))
        self.assertEqual(protocol.public_password_property_reference(b"person", b"secret", challenge), expected)
        self.assertEqual(
            protocol.public_password_property_reference(b"person", b"1234567890abcdef-extra", challenge),
            bytes(left ^ right for left, right in zip(digest, b"1234567890abcdef")),
        )

    def test_property_update_is_right_aligned_and_bounded(self):
        extension = tlv_extension()
        updated = protocol.set_property(extension, 0x2D, LOCAL)
        self.assertEqual(updated[130:136], LOCAL)
        with self.assertRaises(protocol.RuijieProtocolError):
            protocol.set_property(extension, 0x2D, b"too-long")

    def test_v2_check_is_deterministic_and_challenge_bound(self):
        client = self.folder / "8021x.exe"
        client.write_bytes(fake_pe(bytes(range(64))))
        first = protocol.v2_check(bytes(range(16)), client)
        second = protocol.v2_check(bytes(range(1, 17)), client)
        self.assertEqual(len(first), 32)
        self.assertNotEqual(first, second)

    def test_prepare_extension_pins_client_and_updates_dynamic_fields(self):
        client = self.folder / "8021x.exe"
        client.write_bytes(fake_pe(bytes(range(64))))
        profile = protocol.CompatibilityProfile(
            tlv_extension(), bytes(27), ("a" * 64,), hashlib.sha256(client.read_bytes()).hexdigest()
        )
        updated = protocol.prepare_extension(
            profile, bytes(range(16)), client, b"person", b"secret", LOCAL,
            "10.1.2.3", "255.255.255.0", "10.1.2.1", "1.1.1.1",
        )
        self.assertEqual(len(updated), 576)
        self.assertEqual(updated[130:136], LOCAL)
        self.assertEqual(
            protocol.get_property(updated, 0x2F),
            protocol.public_password_property_reference(b"person", b"secret", bytes(range(16))),
        )
        self.assertEqual(protocol.get_property(updated, 0x4D), protocol.public_v4_reference(bytes(range(16))))
        changed = self.folder / "changed.exe"
        changed.write_bytes(client.read_bytes() + b"x")
        with self.assertRaises(protocol.RuijieProtocolError):
            protocol.prepare_extension(
                profile, bytes(range(16)), changed, b"person", b"secret", LOCAL,
                "10.1.2.3", "255.255.255.0", "10.1.2.1", "1.1.1.1",
            )

    def test_eap_packets_declare_only_standard_body_length(self):
        extension = tlv_extension()
        identity = protocol.eap_identity_response(LOCAL, SERVER, 3, "person", extension)
        md5 = protocol.eap_md5_response(LOCAL, SERVER, 4, "person", "secret", bytes(16), extension)
        self.assertEqual(int.from_bytes(identity[16:18], "big"), 11)
        self.assertEqual(int.from_bytes(md5[16:18], "big"), 28)
        self.assertNotIn(b"secret", md5)
        self.assertEqual(len(protocol.eapol_start(LOCAL)), 18)

    def test_success_key_builds_constrained_ruijie_echo(self):
        key = 0x12345678
        body = bytearray(177)
        body[0] = 3
        body[9] = 0
        body[139:143] = bytes(
            protocol._reverse_complement(value) for value in key.to_bytes(4, "big")
        )
        success = ethernet(0, SERVER, LOCAL, bytes(body))
        profile = protocol.CompatibilityProfile(tlv_extension(), bytes(range(27)), ("a" * 64,), "b" * 64)
        sequence = 0x102B
        echo = protocol.echo_frame(profile, LOCAL, SERVER, protocol.echo_key(success), sequence)
        self.assertEqual(len(echo), 45)
        self.assertEqual(echo[:14], SERVER + LOCAL + b"\x88\x8e")
        self.assertEqual(echo[14:18], b"\x01\xbf\x00\x1e")
        expected_key = bytes(
            protocol._reverse_complement(value)
            for value in ((key + sequence) & 0xFFFFFFFF).to_bytes(4, "big")
        )
        expected_sequence = bytes(
            protocol._reverse_complement(value) for value in sequence.to_bytes(4, "big")
        )
        self.assertEqual(echo[24:28], expected_key)
        self.assertEqual(echo[34:38], expected_sequence)


if __name__ == "__main__":
    unittest.main()

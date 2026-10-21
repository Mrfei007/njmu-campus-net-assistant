"""Offline-only comparison of captured Ruijie dynamic fields.

The command intentionally prints booleans and lengths only. It never prints
credentials, packet bytes, MAC addresses, challenges, or calculated hashes.
"""
from __future__ import annotations

import argparse
import hashlib
import re
from pathlib import Path

from campus_net_assistant.credentials import load
from campus_net_assistant.ruijie_protocol import (
    _eapol,
    _ethernet_frames,
    get_property,
    public_password_property_reference,
    public_v4_branch1_reference,
    v2_check,
    v4_check_type,
)
from campus_net_assistant.ruijie_hash import ruijie_sha1_digest
from campus_net_assistant.whirlpool import ruijie_whirlpool_digest


def _loaded_code_image(client: Path) -> bytes:
    """Build the bytes present in the executable's second mapped PE region."""
    data = client.read_bytes()
    pe_offset = int.from_bytes(data[0x3C:0x40], "little")
    section_count = int.from_bytes(data[pe_offset + 6:pe_offset + 8], "little")
    optional_size = int.from_bytes(data[pe_offset + 20:pe_offset + 22], "little")
    table = pe_offset + 24 + optional_size
    for index in range(section_count):
        offset = table + index * 40
        virtual_size = int.from_bytes(data[offset + 8:offset + 12], "little")
        virtual_address = int.from_bytes(data[offset + 12:offset + 16], "little")
        raw_size = int.from_bytes(data[offset + 16:offset + 20], "little")
        raw_pointer = int.from_bytes(data[offset + 20:offset + 24], "little")
        characteristics = int.from_bytes(data[offset + 36:offset + 40], "little")
        if virtual_address == 0x1000 and characteristics & 0x20000000:
            mapped_size = (max(virtual_size, raw_size) + 0xFFF) & ~0xFFF
            return data[raw_pointer:raw_pointer + raw_size].ljust(mapped_size, b"\0")
    raise RuntimeError("client has no mapped executable region")


def _official_v4_branch1_candidates(client: Path, challenge: bytes) -> dict[str, bytes]:
    """Generate bounded offline hypotheses without exposing any digest bytes."""
    from Crypto.Cipher import DES, DES3

    code = _loaded_code_image(client)
    des_key = b"?r^3d)5,"
    triple_key = bytes.fromhex("0123b56789abcdef494567897bcdef01456789abfdef0123")
    stage1 = {"plain": code}
    for operation in ("encrypt", "decrypt"):
        value = bytearray(code)
        cipher = DES3.new(triple_key, DES3.MODE_ECB)
        value[0x400:0x408] = getattr(cipher, operation)(bytes(value[0x400:0x408]))
        stage1[f"triple_{operation}"] = bytes(value)

    transformed: dict[str, bytes] = {}
    for stage_name, value in stage1.items():
        transformed[stage_name] = value
        cipher = DES.new(des_key, DES.MODE_ECB)
        transformed[f"{stage_name}_des_encrypt"] = cipher.encrypt(value)
        transformed[f"{stage_name}_des_decrypt"] = cipher.decrypt(value)

    challenge_sha1 = ruijie_sha1_digest(challenge)
    results = {}
    for name, value in transformed.items():
        material = ruijie_sha1_digest(value) + challenge[:6] + challenge_sha1 + challenge[6:]
        results[name] = ruijie_whirlpool_digest(material).hex().encode("ascii")
    return results


def _find_exchange(capture: Path) -> tuple[bytes, bytes]:
    requests: dict[tuple[bytes, bytes, int], bytes] = {}
    for frame in _ethernet_frames(capture):
        parsed = _eapol(frame)
        if parsed is None:
            continue
        packet_type, body, trailer = parsed
        if packet_type != 0 or len(body) < 6 or body[4] != 4:
            continue
        code, identifier = body[0], body[1]
        source, destination = frame[6:12], frame[:6]
        if code == 1 and body[5] == 16 and len(body) >= 22:
            requests[(source, destination, identifier)] = body[6:22]
        elif code == 2 and body[5] == 16 and trailer:
            challenge = requests.get((destination, source, identifier))
            if challenge is not None:
                return challenge, trailer
    raise RuntimeError("capture has no complete EAP-MD5 exchange")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    parser.add_argument("client", type=Path)
    args = parser.parse_args()

    challenge, extension = _find_exchange(args.capture)
    username, password = load()
    try:
        username_bytes = username.encode("utf-8")
        password_bytes = password.encode("utf-8")
        captured_v2 = get_property(extension, 0x17)
        captured_password = get_property(extension, 0x2F)
        captured_v4 = get_property(extension, 0x4D)
        branch = v4_check_type(challenge)
        print(f"extension_length={len(extension)}")
        print(f"v2_length={len(captured_v2)}")
        print(f"v2_matches_local_client={v2_check(challenge, args.client) == captured_v2}")
        print(f"v2_is_ascii_hex={all(value in b'0123456789abcdefABCDEF' for value in captured_v2)}")
        print(f"v2_has_lowercase_hex={any(value in b'abcdef' for value in captured_v2)}")
        print(f"v2_has_uppercase_hex={any(value in b'ABCDEF' for value in captured_v2)}")
        print(f"v2_has_official_fallback_marker={b'9884773d' in captured_v2.lower()}")
        print(f"password_property_length={len(captured_password)}")
        print(
            "password_property_matches="
            f"{public_password_property_reference(username_bytes, password_bytes, challenge) == captured_password}"
        )
        print(f"v4_branch={branch}")
        print(f"v4_length={len(captured_v4)}")
        embedded_hex = re.findall(rb"(?i)[0-9a-f]{128}", args.client.read_bytes())
        print(f"v4_matches_embedded_constant={captured_v4 in embedded_hex}")
        if branch == 1:
            print(f"public_v4_matches={public_v4_branch1_reference(challenge) == captured_v4}")
            matches = [
                name for name, candidate in _official_v4_branch1_candidates(args.client, challenge).items()
                if candidate == captured_v4
            ]
            print(f"official_v4_candidate_match_count={len(matches)}")
            print(f"official_v4_candidate_match={matches[0] if matches else 'none'}")
        else:
            print("public_v4_matches=not_checked")
    finally:
        password = ""
        password_bytes = b""
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

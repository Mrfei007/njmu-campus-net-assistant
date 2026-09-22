"""Pure Ruijie EAPOL packet preparation and capture-profile extraction.

This module never opens a driver or network adapter.  Imported captures are
reduced to the client extension templates needed for a later field trial; EAP
identities, MAC addresses and server result payloads are not persisted.
"""
from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
from dataclasses import dataclass
from pathlib import Path

from .whirlpool import ruijie_whirlpool_digest


PROFILE_VERSION = 1
MIN_EXTENSION_SIZE = 0x80
MAX_EXTENSION_SIZE = 0x800
PROFILE_PATH_NAME = "ruijie-native-profile.json"
# Digests of MiniEAP's fixed V4 arrays under Ruijie's modified hash functions.
# Keeping only the resulting public constants avoids bundling the old client
# code blobs while reproducing all five public V4 branches byte-for-byte.
_V4_ARRAY_MD5 = bytes.fromhex("5814f36f4cefdf28fb4fe2315e6b5665")
_V4_ARRAY_SHA1 = bytes.fromhex("23754c294acd0ce0321ad20bd4d7c39f8f2c7264")
_V4_ARRAY_RIPEMD128 = bytes.fromhex("373d7a891f120d98ddc2dee2fd428916")
_V4_ARRAY_TIGER = bytes.fromhex("4919a82baec5a7abadffed6875da2360b5f2b7794a7fcc4a")
_V4_ARRAY_1_MD5 = bytes.fromhex("05182cafce93f26a8bef6f4bc0d249c5")
_V4_ARRAY_1_SHA1 = bytes.fromhex("791beac83b62684fa6da7420727612672d3e6398")
_V4_ARRAY_1_RIPEMD128 = bytes.fromhex("fe89f11f5804b40ef16089608b957bee")
_V4_ARRAY_1_TIGER = bytes.fromhex("7e426653ad4a5922e6570b720faf4553f5e694850eee29c2")


class RuijieProtocolError(RuntimeError):
    pass


@dataclass(frozen=True)
class CompatibilityProfile:
    extension: bytes
    echo_body: bytes
    capture_hashes: tuple[str, ...]
    client_sha256: str


def _pcapng_blocks(data: bytes):
    endian = "<"
    offset = 0
    while offset + 12 <= len(data):
        block_type = int.from_bytes(data[offset:offset + 4], "little")
        if block_type == 0x0A0D0D0A:
            magic = data[offset + 8:offset + 12]
            endian = "<" if magic == b"\x4d\x3c\x2b\x1a" else ">" if magic == b"\x1a\x2b\x3c\x4d" else ""
            if not endian:
                raise RuijieProtocolError("抓包的字节序标记无效")
        block_type, length = struct.unpack_from(endian + "II", data, offset)
        if length < 12 or length % 4 or offset + length > len(data):
            raise RuijieProtocolError("抓包包含损坏的数据块")
        if struct.unpack_from(endian + "I", data, offset + length - 4)[0] != length:
            raise RuijieProtocolError("抓包数据块长度校验失败")
        yield endian, block_type, data[offset + 8:offset + length - 4]
        offset += length
    if offset != len(data):
        raise RuijieProtocolError("抓包末尾包含无法识别的数据")


def _ethernet_frames(path: Path) -> list[bytes]:
    if path.suffix.casefold() != ".pcapng" or path.stat().st_size > 128 * 1024 * 1024:
        raise RuijieProtocolError("请选择不超过 128 MB 的 pcapng 抓包")
    interfaces: list[int] = []
    result = []
    for endian, block_type, body in _pcapng_blocks(path.read_bytes()):
        if block_type == 1 and len(body) >= 8:
            interfaces.append(struct.unpack_from(endian + "H", body, 0)[0])
        elif block_type == 6 and len(body) >= 20:
            interface, _, _, captured, _ = struct.unpack_from(endian + "IIIII", body, 0)
            if interface >= len(interfaces) or interfaces[interface] != 1:
                continue
            result.append(body[20:20 + captured])
    return result


def _eapol(frame: bytes) -> tuple[int, bytes, bytes] | None:
    if len(frame) < 18:
        return None
    offset = 14
    ethertype = frame[12:14]
    if ethertype in (b"\x81\x00", b"\x88\xa8") and len(frame) >= 22:
        ethertype = frame[16:18]
        offset = 18
    if ethertype != b"\x88\x8e":
        return None
    packet_type = frame[offset + 1]
    body_length = int.from_bytes(frame[offset + 2:offset + 4], "big")
    end = offset + 4 + body_length
    if end > len(frame):
        # Ruijie 4.99 keepalives declare 30 but intentionally carry 27 bytes.
        if packet_type == 0xBF and body_length == 30 and len(frame) - offset - 4 == 27:
            return packet_type, frame[offset + 4:], b""
        return None
    return packet_type, frame[offset + 4:end], frame[end:]


def _valid_extension(value: bytes) -> bool:
    return MIN_EXTENSION_SIZE <= len(value) <= MAX_EXTENSION_SIZE and any(value)


def _zero_occurrences(buffer: bytearray, value: bytes) -> None:
    if len(value) < 4:
        return
    start = 0
    while True:
        start = buffer.find(value, start)
        if start < 0:
            return
        buffer[start:start + len(value)] = b"\0" * len(value)
        start += len(value)


def _redact_capture_templates(extension: bytes, echo_body: bytes, source: bytes,
                              identity: bytes) -> tuple[bytes, bytes]:
    """Remove per-machine and per-session fields before persisting a profile."""
    clean_extension = bytearray(extension)
    clean_extension[:0x17] = b"\0" * min(0x17, len(clean_extension))
    # Remove every captured field tied to credentials, a session, the local
    # adapter, local addressing, or a storage device. Compatibility constants
    # such as the client name/version and service name are retained.
    for property_type in (
        0x17,  # challenge-dependent V2 check
        0x18,  # DHCP state
        0x2D,  # MAC address
        0x2F,  # username/password/challenge-derived value
        0x36,  # link-local IPv6 address
        0x38,  # temporary link-local IPv6 address
        0x4E,  # global IPv6 address
        0x4D,  # challenge-dependent V3/V4 hash
        0x54,  # hard-disk serial number
        0x76,  # secondary DNS address
    ):
        try:
            value = get_property(bytes(clean_extension), property_type)
            clean_extension = bytearray(set_property(bytes(clean_extension), property_type, b"\0" * len(value)))
        except RuijieProtocolError:
            pass
    _zero_occurrences(clean_extension, source)
    _zero_occurrences(clean_extension, identity)

    clean_echo = bytearray(echo_body)
    clean_echo[6:10] = b"\0" * 4
    clean_echo[16:20] = b"\0" * 4
    _zero_occurrences(clean_echo, source)
    _zero_occurrences(clean_echo, identity)
    return bytes(clean_extension), bytes(clean_echo)


def extract_compatibility_profile(captures: list[Path], client_exe: Path) -> CompatibilityProfile:
    if not captures:
        raise RuijieProtocolError("请选择至少一个成功认证抓包")
    if not client_exe.is_file():
        raise RuijieProtocolError("未找到官方 8021x.exe")
    extension = None
    echo_body = None
    hashes = []
    for path in captures:
        raw_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        hashes.append(raw_hash)
        frames = _ethernet_frames(path)
        unique = []
        seen = set()
        for frame in frames:
            digest = hashlib.sha256(frame).digest()
            if digest not in seen:
                seen.add(digest)
                unique.append(frame)
        md5_candidates: list[tuple[bytes, bytes]] = []
        successful_servers: set[bytes] = set()
        echoes: list[tuple[bytes, bytes]] = []
        for frame in unique:
            parsed = _eapol(frame)
            if parsed is None:
                continue
            packet_type, body, trailer = parsed
            source, destination = frame[6:12], frame[:6]
            if packet_type == 0 and len(body) >= 4:
                if len(body) >= 5 and body[0] == 2 and body[4] == 4 and _valid_extension(trailer):
                    md5_candidates.append((source + destination, trailer))
                elif body[0] == 3:
                    successful_servers.add(destination + source)
            elif packet_type == 0xBF and len(body) == 27:
                echoes.append((source, body))
        for direction, candidate in md5_candidates:
            if direction in successful_servers:
                source = direction[:6]
                captured_echo = next((body for echo_source, body in echoes if echo_source == source), None)
                if captured_echo is not None:
                    identity = next(
                        (body[22:] for frame in unique
                         if (parsed := _eapol(frame)) is not None
                         and parsed[0] == 0 and len((body := parsed[1])) >= 22
                         and body[0] == 2 and body[4:6] == b"\x04\x10"
                         and frame[6:12] == source),
                        b"",
                    )
                    extension, echo_body = _redact_capture_templates(
                        candidate, captured_echo, source, identity
                    )
    if extension is None:
        raise RuijieProtocolError("抓包中没有找到同一会话的 EAP-MD5 响应和认证成功报文")
    if echo_body is None:
        raise RuijieProtocolError("抓包中没有找到认证成功后的锐捷保活报文")
    return CompatibilityProfile(
        extension=extension,
        echo_body=echo_body,
        capture_hashes=tuple(hashes),
        client_sha256=hashlib.sha256(client_exe.read_bytes()).hexdigest(),
    )


def profile_json(profile: CompatibilityProfile) -> str:
    payload = {
        "version": PROFILE_VERSION,
        "extension": base64.b64encode(profile.extension).decode("ascii"),
        "echo_body": base64.b64encode(profile.echo_body).decode("ascii"),
        "capture_sha256": list(profile.capture_hashes),
        "client_sha256": profile.client_sha256,
        "privacy": (
            "Credentials, EAP identities, MAC/IP addresses, hardware identifiers "
            "and server result payloads are not stored."
        ),
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)


def load_profile(text: str) -> CompatibilityProfile:
    try:
        payload = json.loads(text)
        if payload.get("version") != PROFILE_VERSION:
            raise ValueError
        extension = base64.b64decode(payload["extension"], validate=True)
        echo_body = base64.b64decode(payload["echo_body"], validate=True)
        captures = tuple(payload["capture_sha256"])
        client_hash = payload["client_sha256"]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise RuijieProtocolError("锐捷兼容资料格式无效") from None
    if not _valid_extension(extension) or len(echo_body) != 27:
        raise RuijieProtocolError("锐捷兼容资料中的报文模板长度无效")
    if not captures or not all(isinstance(value, str) and len(value) == 64 for value in captures):
        raise RuijieProtocolError("锐捷兼容资料缺少抓包校验值")
    if not isinstance(client_hash, str) or len(client_hash) != 64:
        raise RuijieProtocolError("锐捷兼容资料缺少客户端校验值")
    return CompatibilityProfile(extension, echo_body, captures, client_hash)


def md5_response(identifier: int, password: str, challenge: bytes) -> bytes:
    if not 0 <= identifier <= 255 or not challenge:
        raise RuijieProtocolError("EAP-MD5 挑战参数无效")
    secret = password.encode("utf-8")
    try:
        return hashlib.md5(bytes([identifier]) + secret + challenge).digest()
    finally:
        secret = b""


def _reverse_complement(value: int) -> int:
    reversed_bits = int(f"{value:08b}"[::-1], 2)
    return reversed_bits ^ 0xFF


def network_header(ip: str, mask: str, gateway: str, dns: str, dhcp: bool) -> bytes:
    header = bytearray(0x17)
    header[2:4] = b"\x13\x11"
    header[4] = int(dhcp)
    for offset, address in ((5, ip), (9, mask), (13, gateway), (17, dns)):
        try:
            header[offset:offset + 4] = socket.inet_aton(address)
        except OSError:
            raise RuijieProtocolError("有线网卡的 IPv4 参数无效") from None
    crc = 0
    for value in header[:0x15]:
        crc ^= value << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    header[0x15] = crc >> 8
    header[0x16] = crc & 0xFF
    return bytes(_reverse_complement(value) for value in header)


def set_property(extension: bytes, property_type: int, value: bytes) -> bytes:
    output = bytearray(extension)
    cursor = 0x46
    while cursor + 6 <= len(output):
        base = cursor + 2 if output[cursor] == 0x1A else cursor
        if base + 6 > len(output) or output[base:base + 4] != b"\x00\x00\x13\x11":
            break
        item_type = output[base + 4]
        item_length = output[base + 5]
        end = base + 4 + item_length
        if item_length < 2 or end > len(output):
            break
        if item_type == property_type:
            if len(value) > item_length - 2:
                raise RuijieProtocolError(f"锐捷属性 0x{property_type:02x} 的值过长")
            start = end - len(value)
            output[start:end] = value
            return bytes(output)
        cursor = end
    raise RuijieProtocolError(f"抓包模板缺少锐捷属性 0x{property_type:02x}")


def get_property(extension: bytes, property_type: int) -> bytes:
    cursor = 0x46
    while cursor + 6 <= len(extension):
        base = cursor + 2 if extension[cursor] == 0x1A else cursor
        if base + 6 > len(extension) or extension[base:base + 4] != b"\x00\x00\x13\x11":
            break
        item_type = extension[base + 4]
        item_length = extension[base + 5]
        end = base + 4 + item_length
        if item_length < 2 or end > len(extension):
            break
        if item_type == property_type:
            return extension[base + 6:end]
        cursor = end
    raise RuijieProtocolError(f"抓包模板缺少锐捷属性 0x{property_type:02x}")


def executable_code(path: Path) -> bytes:
    data = path.read_bytes()
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise RuijieProtocolError("官方 8021x.exe 不是有效 PE 文件")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_offset:pe_offset + 4] != b"PE\0\0":
        raise RuijieProtocolError("官方 8021x.exe 的 PE 头无效")
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    table = pe_offset + 24 + optional_size
    for index in range(section_count):
        offset = table + index * 40
        raw_size, raw_pointer = struct.unpack_from("<II", data, offset + 16)
        characteristics = struct.unpack_from("<I", data, offset + 36)[0]
        if characteristics & 0x20000000 or characteristics & 0x00000020:
            end = raw_pointer + raw_size
            if raw_pointer <= len(data) and end <= len(data) and raw_size >= 8:
                return data[raw_pointer:end]
    raise RuijieProtocolError("官方 8021x.exe 没有可用的代码段")


def v2_check(challenge: bytes, client_exe: Path) -> bytes:
    if len(challenge) != 16:
        raise RuijieProtocolError("客户端 V2 校验需要 16 字节挑战")
    code = executable_code(client_exe)
    chunk_size = len(code) // 8
    if chunk_size == 0:
        raise RuijieProtocolError("官方客户端代码段过小")
    table = bytearray()
    for index in range(8):
        chunk = code[index * chunk_size:(index + 1) * chunk_size]
        table.append(challenge[index * 2])
        table.extend(hashlib.md5(challenge + chunk).digest())
        table.append(challenge[index * 2 + 1])
    return hashlib.md5(table).hexdigest().encode("ascii")


def v4_check_type(challenge: bytes) -> int:
    """Return MiniEAP's uint32 C branch selector for a 16-byte challenge."""
    if len(challenge) != 16:
        raise RuijieProtocolError("客户端 V4 校验需要 16 字节挑战")
    first = challenge[0] if challenge[0] < 0x80 else challenge[0] - 0x100
    fourth = challenge[3] if challenge[3] < 0x80 else challenge[3] - 0x100
    return ((first + fourth) & 0xFFFFFFFF) % 5


def _signed_hex_byte(value: int) -> bytes:
    """Match C's ``sprintf("%02x", (signed char)value)`` output."""
    signed = value if value < 0x80 else value - 0x100
    return (f"{signed & 0xFFFFFFFF:02x}" if signed < 0 else f"{signed:02x}").encode("ascii")


def public_v4_reference(challenge: bytes) -> bytes:
    """Reproduce MiniEAP's complete five-branch Ruijie V4 check."""
    branch = v4_check_type(challenge)
    if branch == 0:
        material = bytearray(_V4_ARRAY_MD5.hex().encode("ascii"))
        for index in range(0, 16, 2):
            material.extend(_signed_hex_byte(challenge[index]))
        material.extend(_V4_ARRAY_1_MD5.hex().encode("ascii"))
        for index in range(1, 16, 2):
            material.extend(_signed_hex_byte(challenge[index]))
        # The original implementation unconditionally hashes 0x60 bytes.
        material = bytes(material[:0x60])
    elif branch == 1:
        material = _V4_ARRAY_1_SHA1 + challenge[:6] + _V4_ARRAY_SHA1 + challenge[6:]
    elif branch == 2:
        material = _V4_ARRAY_1_SHA1 + challenge[:6] + _V4_ARRAY_RIPEMD128 + challenge[6:]
    elif branch == 3:
        material = _V4_ARRAY_TIGER + challenge[:10] + _V4_ARRAY_1_RIPEMD128 + challenge[10:]
    else:
        material = _V4_ARRAY_1_TIGER + challenge[:8] + _V4_ARRAY_SHA1 + challenge[8:]
    return ruijie_whirlpool_digest(material).hex().encode("ascii")


def public_v4_branch1_reference(challenge: bytes) -> bytes:
    """Compatibility wrapper retained for callers that require branch 1."""
    branch = v4_check_type(challenge)
    if branch != 1:
        raise RuijieProtocolError(f"需要锐捷 V4 分支 1，收到分支 {branch}")
    return public_v4_reference(challenge)


def public_password_property_reference(username: bytes, password: bytes, challenge: bytes) -> bytes:
    """Reproduce MiniEAP's 0x2f formula from already encoded bytes."""
    if len(challenge) != 16:
        raise RuijieProtocolError("密码属性需要 16 字节挑战")
    if not isinstance(username, bytes) or not isinstance(password, bytes):
        raise TypeError("username and password must be bytes")
    password_block = password[:16].ljust(16, b"\0")
    digest = hashlib.md5(username + challenge).digest()
    return bytes(left ^ right for left, right in zip(digest, password_block))


def prepare_extension(
    profile: CompatibilityProfile,
    challenge: bytes,
    client_exe: Path,
    username: bytes,
    password: bytes,
    mac: bytes,
    ip: str,
    mask: str,
    gateway: str,
    dns: str,
    dhcp: bool = True,
) -> bytes:
    if len(challenge) != 16:
        raise RuijieProtocolError("锐捷私有扩展需要 16 字节挑战")
    if len(mac) != 6:
        raise RuijieProtocolError("有线网卡 MAC 长度无效")
    if hashlib.sha256(client_exe.read_bytes()).hexdigest() != profile.client_sha256:
        raise RuijieProtocolError("官方 8021x.exe 与生成兼容资料时的文件不一致")
    extension = network_header(ip, mask, gateway, dns, dhcp) + profile.extension[0x17:]
    extension = set_property(extension, 0x2D, mac)
    extension = set_property(extension, 0x18, bytes([int(dhcp)]))
    extension = set_property(extension, 0x17, v2_check(challenge, client_exe))
    extension = set_property(
        extension, 0x2F,
        public_password_property_reference(username, password, challenge),
    )
    return set_property(extension, 0x4D, public_v4_reference(challenge))


def eapol_start(source: bytes, destination: bytes = b"\x01\x80\xc2\x00\x00\x03") -> bytes:
    if len(source) != 6 or len(destination) != 6:
        raise RuijieProtocolError("以太网地址长度无效")
    return destination + source + b"\x88\x8e\x01\x01\x00\x00"


def eap_identity_response(source: bytes, destination: bytes, identifier: int, username: str, extension: bytes) -> bytes:
    identity = username.encode("utf-8")
    eap = bytes([2, identifier]) + struct.pack("!H", 5 + len(identity)) + b"\x01" + identity
    return destination + source + b"\x88\x8e\x01\x00" + struct.pack("!H", len(eap)) + eap + extension


def eap_md5_response(source: bytes, destination: bytes, identifier: int, username: str, password: str,
                     challenge: bytes, extension: bytes) -> bytes:
    identity = username.encode("utf-8")
    response = md5_response(identifier, password, challenge)
    eap = bytes([2, identifier]) + struct.pack("!H", 6 + len(response) + len(identity)) + b"\x04\x10" + response + identity
    return destination + source + b"\x88\x8e\x01\x00" + struct.pack("!H", len(eap)) + eap + extension


def echo_key(success_frame: bytes) -> int:
    parsed = _eapol(success_frame)
    if parsed is None or parsed[0] != 0 or len(parsed[1]) < 10 or parsed[1][0] != 3:
        raise RuijieProtocolError("报文不是包含私有数据的 EAP Success")
    body = parsed[1]
    offset = 139 + body[9]
    if offset + 4 > len(body):
        raise RuijieProtocolError("EAP Success 中没有可用的锐捷保活密钥")
    decoded = bytes(_reverse_complement(value) for value in body[offset:offset + 4])
    return int.from_bytes(decoded, "big")


def echo_frame(profile: CompatibilityProfile, source: bytes, destination: bytes,
               key: int, sequence: int) -> bytes:
    if len(source) != 6 or len(destination) != 6:
        raise RuijieProtocolError("以太网地址长度无效")
    if not 0 <= key <= 0xFFFFFFFF or not 0 <= sequence <= 0xFFFFFFFF:
        raise RuijieProtocolError("锐捷保活计数参数无效")
    body = bytearray(profile.echo_body)
    for index, value in enumerate(((key + sequence) & 0xFFFFFFFF).to_bytes(4, "big")):
        body[6 + index] = _reverse_complement(value)
    for index, value in enumerate(sequence.to_bytes(4, "big")):
        body[16 + index] = _reverse_complement(value)
    # Ruijie 4.99 declares 30 bytes while its observed frame contains 27.
    return destination + source + b"\x88\x8e\x01\xbf\x00\x1e" + bytes(body)


def eapol_logoff(source: bytes, destination: bytes, extension: bytes) -> bytes:
    if len(source) != 6 or len(destination) != 6:
        raise RuijieProtocolError("以太网地址长度无效")
    return destination + source + b"\x88\x8e\x01\x02\x00\x00" + extension

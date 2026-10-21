"""Protocol-specific hash primitives used by Ruijie V4 compatibility.

These are deliberately separate from standard cryptographic hashes: the
client's SHA-1-like function changes its IV, constants and round boundaries.
"""
from __future__ import annotations


_MASK32 = (1 << 32) - 1
_INITIAL_STATE = (0x32075416, 0xF8DAE9BC, 0x73541260, 0x8ACB9DFE, 0xFD0C2E1B)


def _rotate_left(value: int, count: int) -> int:
    return ((value << count) | (value >> (32 - count))) & _MASK32


def _process_block(state: list[int], block: bytes) -> None:
    words = [int.from_bytes(block[index:index + 4], "big") for index in range(0, 64, 4)]
    for index in range(16, 80):
        words.append(_rotate_left(words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16], 1))

    a, b, c, d, e = state
    first_byte = block[0]
    for index in range(80):
        if index < 20:
            function = ((c ^ d) & b) ^ d
            constant = -0x5D6AA4D4
        elif index < 40:
            function = b ^ c ^ d
            constant = 0x16AE9DEB + first_byte
        elif index < 61:
            function = (b & c) | (b & d) | (c & d)
            constant = -0x34032E48
        else:
            function = b ^ c ^ d
            constant = -0x5CD39E93
        temporary = (_rotate_left(a, 5) + function + e + words[index] + constant) & _MASK32
        e, d, c, b, a = d, c, _rotate_left(b, 30), a, temporary

    state[0] = (state[0] + a + 1) & _MASK32
    state[1] = (state[1] + b) & _MASK32
    state[2] = (state[2] + c) & _MASK32
    state[3] = (state[3] + d) & _MASK32
    state[4] = (state[4] + e) & _MASK32


def ruijie_sha1_digest(data: bytes) -> bytes:
    """Return the 20-byte digest from Ruijie's modified SHA-1 primitive."""
    if not isinstance(data, bytes):
        raise TypeError("Ruijie SHA-1 input must be bytes")
    bit_length = len(data) * 8
    padded = bytearray(data)
    padded.append(0x80)
    padded.extend(b"\0" * ((56 - len(padded)) % 64))
    padded.extend(bit_length.to_bytes(8, "big"))
    state = list(_INITIAL_STATE)
    for offset in range(0, len(padded), 64):
        _process_block(state, padded[offset:offset + 64])
    return b"".join(value.to_bytes(4, "big") for value in state)

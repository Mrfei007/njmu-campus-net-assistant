"""Small, dependency-free implementation of the ISO Whirlpool hash.

The structure follows the public-domain reference implementation by
Paulo S. L. M. Barreto and Vincent Rijmen.  It intentionally exposes only a
one-shot digest function because the Ruijie compatibility calculation hashes
one short, fixed-size input.
"""
from __future__ import annotations


_MASK64 = (1 << 64) - 1
_SBOX = bytes.fromhex(
    "1823c6e887b8014f36a6d2f5796f915260bc9b8ea30c7b351de0d7c22e4bfe57"
    "157737e59ff04ada58c9290ab1a06b85bd5d10f4cb3e0567e427418ba77d95d8"
    "fbee7c66dd17479eca2dbf07ad5a83336302aa71c81949d9f2e35b889a2632b0"
    "e90fd580becd3448ff7a905f20681aaeb454932264f173124008c3ecdba18d3d9"
    "700cf2b7682d61bb5af6a5045f330ef3f55a2ea65ba2fc0de1cfd4d9275068ab"
    "2e60e1f62d4a896f9c525598472394c5e78388cd1a5e261b3219c1e43c7fc045"
    "1996d0dfadf7e243babce118f4eb7eb3c8194f7b9132cd3e76ec40356447fa92a"
    "bbc153dc0b9d6c3174f646ac8914e1163a690970b6d0edcc4298a4285cf886"
)
_ROUND_CONSTANTS = (
    0x1823C6E887B8014F,
    0x36A6D2F5796F9152,
    0x60BC9B8EA30C7B35,
    0x1DE0D7C22E4BFE57,
    0x157737E59FF04ADA,
    0x58C9290AB1A06B85,
    0xBD5D10F4CB3E0567,
    0xE427418BA77D95D8,
    0xFBEE7C66DD17479E,
    0xCA2DBF07AD5A8333,
)


def _multiply_by_two(value: int) -> int:
    value <<= 1
    return (value ^ 0x11D) & 0xFF if value & 0x100 else value


def _make_tables() -> tuple[tuple[int, ...], ...]:
    first = []
    for value in _SBOX:
        value2 = _multiply_by_two(value)
        value4 = _multiply_by_two(value2)
        value8 = _multiply_by_two(value4)
        row = (value, value, value4, value, value8, value4 ^ value, value2, value8 ^ value)
        first.append(int.from_bytes(row, "big"))
    tables = [tuple(first)]
    for shift in range(8, 64, 8):
        tables.append(tuple(((value >> shift) | (value << (64 - shift))) & _MASK64 for value in first))
    return tuple(tables)


_TABLES = _make_tables()
_RUIJIE_TABLE_OVERRIDES = {
    (0, 0): 0x18186018C07A30D8, (0, 1): 0x23238C2305AF4A26,
    (0, 2): 0xCAC63FC67EF991B8, (0, 3): 0xE8E8A7E8136FCDFB,
    (0, 4): 0x8787F6874CA113CB, (0, 5): 0xB8B8DAB8A9626DB1,
    (0, 6): 0x0101040108B50209, (0, 7): 0x4FBF214F426E9E0D,
    (0, 12): 0x7979FE79EF80F296, (0, 16): 0x60609DCD27FDC047,
    (0, 35): 0xE5E5CAE57B56D79E, (0, 38): 0x4A4A35546A7F9420,
    (0, 40): 0x58587D58FFF5B0A2, (0, 44): 0xB1B1FEB1EA2F7F50,
    (0, 54): 0x05053F0528110A2D, (0, 56): 0xE4E4B7E473E3D597,
    (0, 66): 0x7C7CE20CC791F8BB, (0, 137): 0xAFAF86AFA22943BE,
    (0, 157): 0x7575C9758FFEEAFA, (0, 189): 0xC7C73BC7790C93B1,
    (0, 192): 0x515159521208A2E3, (0, 249): 0x4242154223578468,
    (3, 23): 0xE16A82B535D435B5, (3, 24): 0x693AF51D1D2C1DE8,
    (3, 25): 0x47DDB3E0E0A57053, (3, 51): 0x03F506C4F4F7F4F3,
    (3, 53): 0xC67CD33E31083EED, (3, 70): 0x468E45475C014702,
    (3, 77): 0x2FB4B0BB5A755AEA, (3, 101): 0xDE87EBA9CD13CD26,
    (3, 110): 0x72340A1A1A681AD0, (3, 204): 0x89EF838F8F068F0C,
    (3, 237): 0x970FB58A491E893C, (7, 6): 0x0104010805020911,
    (7, 26): 0xD77BD7FC0CB321D7, (7, 32): 0x155415A84EEABD15,
    (7, 39): 0xDA8EDA9E95A944DA, (7, 47): 0x852E855CA9A7D985,
    (7, 63): 0xD820D88E9FAD56D8, (7, 74): 0xBFC6BF96D9632EBF,
    (7, 77): 0x5A755AEA88B4B05A, (7, 85): 0x19D019C87D32D119,
    (7, 129): 0x0210000000000000, (7, 161): 0xE6BFE50359D185E6,
    (7, 248): 0xCC12AC2EDB85E2CC, (7, 253): 0x5C6DC7DA31B8865C,
}


def _make_ruijie_tables() -> tuple[tuple[int, ...], ...]:
    tables = [list(table) for table in _TABLES]
    for (table, index), value in _RUIJIE_TABLE_OVERRIDES.items():
        tables[table][index] = value
    return tuple(tuple(table) for table in tables)


_RUIJIE_TABLES = _make_ruijie_tables()


def _transform(words: list[int], tables: tuple[tuple[int, ...], ...] = _TABLES) -> list[int]:
    output = []
    for column in range(8):
        value = 0
        for row, table in enumerate(tables):
            source = words[(column - row) & 7]
            value ^= table[(source >> (56 - 8 * row)) & 0xFF]
        output.append(value)
    return output


def _compress(current_hash: list[int], block_bytes: bytes, ruijie_variant: bool = False) -> None:
    block = [int.from_bytes(block_bytes[index:index + 8], "big") for index in range(0, 64, 8)]
    key = current_hash.copy()
    state = [block[index] ^ key[index] for index in range(8)]
    tables = _RUIJIE_TABLES if ruijie_variant else _TABLES
    for round_constant in _ROUND_CONSTANTS:
        key = _transform(key, tables)
        key[0] ^= round_constant
        state = [value ^ key[index] for index, value in enumerate(_transform(state, tables))]
        if ruijie_variant:
            # The Ruijie V4 implementation intentionally perturbs these three
            # words after every Whirlpool round.
            for index in (2, 5, 6):
                state[index] = (state[index] + 1) & _MASK64
    for index in range(8):
        current_hash[index] ^= state[index] ^ block[index]


def _digest(data: bytes, state: list[int], ruijie_variant: bool = False) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("Whirlpool input must be bytes")
    bit_length = len(data) * 8
    padded = bytearray(data)
    padded.append(0x80)
    padded.extend(b"\0" * ((32 - len(padded)) % 64))
    padded.extend(bit_length.to_bytes(32, "big"))
    for offset in range(0, len(padded), 64):
        _compress(state, padded[offset:offset + 64], ruijie_variant)
    return b"".join(value.to_bytes(8, "big") for value in state)


def whirlpool_digest(data: bytes) -> bytes:
    """Return the 64-byte ISO Whirlpool digest of *data*."""
    return _digest(data, [0] * 8)


def ruijie_whirlpool_digest(data: bytes) -> bytes:
    """Return the protocol-specific Whirlpool variant used by Ruijie V4."""
    return _digest(data, [0, 3, 5, 2, 1, 7, 4, 6], ruijie_variant=True)

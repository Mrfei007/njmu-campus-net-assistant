"""Disassemble a selected virtual-address range in a PE file."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("start", type=lambda value: int(value, 0))
    parser.add_argument("size", type=lambda value: int(value, 0))
    args = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".research" / "pydeps"))
    import pefile
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    pe = pefile.PE(str(args.binary))
    base = pe.OPTIONAL_HEADER.ImageBase
    mode = CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else CS_MODE_32
    rva = args.start - base if args.start >= base else args.start
    code = pe.get_data(rva, args.size)
    md = Cs(CS_ARCH_X86, mode)
    for insn in md.disasm(code, base + rva):
        print(f"0x{insn.address:x}\t{insn.mnemonic}\t{insn.op_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

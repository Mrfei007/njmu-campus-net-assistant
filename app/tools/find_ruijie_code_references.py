"""Find direct code references to selected virtual addresses in a PE file."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("targets", nargs="+", type=lambda value: int(value, 0))
    args = parser.parse_args()
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / ".research" / "pydeps"))
    import pefile
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

    pe = pefile.PE(str(args.binary))
    image_base = pe.OPTIONAL_HEADER.ImageBase
    mode = CS_MODE_64 if pe.FILE_HEADER.Machine == 0x8664 else CS_MODE_32
    targets = set(args.targets)
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    md.skipdata = True
    for section in pe.sections:
        if not section.Characteristics & 0x20000000:
            continue
        code = section.get_data()
        base = image_base + section.VirtualAddress
        for insn in md.disasm(code, base):
            if insn.id == 0:
                continue
            for operand in insn.operands:
                target = None
                if operand.type == X86_OP_IMM:
                    target = operand.imm
                elif operand.type == X86_OP_MEM and mode == CS_MODE_64 and operand.mem.base == X86_REG_RIP:
                    target = insn.address + insn.size + operand.mem.disp
                elif operand.type == X86_OP_MEM and mode == CS_MODE_32 and operand.mem.base == 0:
                    target = operand.mem.disp & 0xFFFFFFFF
                if target in targets:
                    print(f"0x{insn.address:x}\t{insn.mnemonic}\t{insn.op_str}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

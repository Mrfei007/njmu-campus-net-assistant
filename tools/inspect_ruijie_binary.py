"""Print selected strings and code references from the local Ruijie worker."""
from __future__ import annotations

import argparse
import re
import struct
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("client", type=Path)
    args = parser.parse_args()
    deps = Path(__file__).resolve().parents[1] / ".research" / "pydeps"
    sys.path.insert(0, str(deps))
    import pefile
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

    pe = pefile.PE(str(args.client), fast_load=False)
    image_base = pe.OPTIONAL_HEADER.ImageBase
    machine = pe.FILE_HEADER.Machine
    mode = CS_MODE_64 if machine == 0x8664 else CS_MODE_32
    selected: dict[int, str] = {}
    keywords = re.compile(r"v4|checkdata|checkxp|md5|sha|tiger|whirl|ripemd|8021x", re.I)
    for section in pe.sections:
        data = section.get_data()
        section_va = image_base + section.VirtualAddress
        for match in re.finditer(rb"[ -~]{4,}", data):
            value = match.group().decode("ascii", "replace")
            if keywords.search(value) or re.fullmatch(r"(?i)[0-9a-f]{128}", value):
                selected[section_va + match.start()] = value[:160]
        for match in re.finditer(rb"(?:[ -~]\x00){4,}", data):
            raw = match.group()
            value = raw.decode("utf-16-le", "replace")
            if keywords.search(value):
                selected[section_va + match.start()] = value[:160]

    print(f"machine=0x{machine:04x}")
    for address, value in sorted(selected.items()):
        print(f"string=0x{address:x} {value!r}")

    code_sections = [s for s in pe.sections if s.Characteristics & 0x20000000]
    md = Cs(CS_ARCH_X86, mode)
    md.detail = True
    md.skipdata = True
    references: list[tuple[int, int]] = []
    targets = set(selected)
    for section in code_sections:
        code = section.get_data()
        base = image_base + section.VirtualAddress
        for insn in md.disasm(code, base):
            if insn.id == 0:
                continue
            for operand in insn.operands:
                target = None
                if operand.type == X86_OP_IMM:
                    target = operand.imm
                elif operand.type == X86_OP_MEM:
                    if mode == CS_MODE_32 and operand.mem.base == 0:
                        target = operand.mem.disp & 0xFFFFFFFF
                    elif mode == CS_MODE_64 and operand.mem.base == X86_REG_RIP:
                        target = insn.address + insn.size + operand.mem.disp
                if target in targets:
                    references.append((insn.address, target))
    for source, target in references:
        print(f"xref=0x{source:x}->0x{target:x} {selected[target]!r}")

    for string_address, value in selected.items():
        if value != "cV4Api":
            continue
        descriptor_rva = string_address - image_base - 16
        needle = struct.pack("<I", descriptor_rva)
        raw = bytes(pe.__data__)
        for match in re.finditer(re.escape(needle), raw):
            try:
                field_rva = pe.get_rva_from_offset(match.start())
                col_rva = field_rva - 12
                col_offset = pe.get_offset_from_rva(col_rva)
                signature, _, _, type_rva, _, self_rva = struct.unpack_from("<IIIIII", raw, col_offset)
            except (ValueError, struct.error):
                continue
            if signature != 1 or type_rva != descriptor_rva or self_rva != col_rva:
                continue
            col_address = image_base + col_rva
            pointer = struct.pack("<Q", col_address)
            for ptr_match in re.finditer(re.escape(pointer), raw):
                try:
                    ptr_rva = pe.get_rva_from_offset(ptr_match.start())
                except ValueError:
                    continue
                functions = []
                cursor = ptr_match.start() + 8
                while cursor + 8 <= len(raw) and len(functions) < 24:
                    function = struct.unpack_from("<Q", raw, cursor)[0]
                    if not any(
                        image_base + s.VirtualAddress <= function < image_base + s.VirtualAddress + s.Misc_VirtualSize
                        for s in code_sections
                    ):
                        break
                    functions.append(function)
                    cursor += 8
                if functions:
                    joined = ",".join(f"0x{x:x}" for x in functions)
                    print(f"vtable=0x{image_base + ptr_rva + 8:x} functions={joined}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

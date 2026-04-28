/// MMIO instruction decoder for x86-64 long mode.
/// Decodes MOV instructions at guest RIP to emulate LAPIC/IOAPIC MMIO.
/// Handles the instruction patterns Linux writel()/readl() compile to.
///
/// Supported opcodes:
///   0x89 MOV r/m32, r32    (MMIO write from register)
///   0x8B MOV r32, r/m32    (MMIO read to register)
///   0xC7 MOV r/m32, imm32  (MMIO write immediate)
///   0x88 MOV r/m8, r8      (MMIO write byte)
///   0x8A MOV r8, r/m8      (MMIO read byte)
///
/// Guest virtual -> physical translation via 4-level page table walk,
/// reading guest physical memory through the kernel physmap.
// MMIO instruction byte decoder used by exception/fault paths to inspect
// faulting MOV opcodes. The full guest-virt → guest-phys → instruction
// fetch pipeline is parked along with the spec-v2 KVM run loop; only the
// pure byte-buffer decoder (`decodeBytes`) is wired today.


/// Result of decoding an MMIO instruction.
pub const MmioOp = struct {
    is_write: bool,
    size: u8, // 1, 2, or 4 bytes
    reg: u4, // GPR index (destination for reads, source for register writes)
    value: u32, // Write value (from register or immediate)
    len: u8, // Total instruction length for RIP advancement
    is_immediate: bool = false, // true for MOV imm (0xC7), false for register-source writes
};

pub const DecodeError = error{
    UnsupportedInstruction,
    IncompleteDecode,
};

// --- Instruction decode ---

/// Decode MMIO/port I/O instruction from a pre-fetched byte buffer.
/// Returns the decoded operation or an error if the instruction is
/// unsupported or the buffer is too short.
///
/// Follows the general 64-bit instruction format from Intel SDM Vol 2A
/// §2.1 "Instruction Format":
///   [Legacy Prefix][REX Prefix][Opcode][ModR/M][SIB][Displacement][Immediate]
///
/// For register-source writes (0x89, 0x88), `is_immediate` is false and
/// `value` is 0 — the caller must read the source register via `reg`.
pub fn decodeBytes(buf: []const u8) DecodeError!MmioOp {
    if (buf.len < 2) return DecodeError.IncompleteDecode;

    var i: u8 = 0;
    var rex: u8 = 0;
    var has_66: bool = false;
    var has_rex_w: bool = false;

    // Parse legacy + REX prefixes.
    // REX: Intel SDM Vol 2A §2.2.1 Table 2-4 (REX.W is bit 3 of the
    // 0x40..0x4F prefix byte; promotes the operand to 64-bit).
    // 0x66: operand-size override (SDM Vol 2A §2.1.1) — switches 32-bit
    // default to 16-bit in this context.
    // 0x67/0xF0/0xF2/0xF3/segment-overrides: skipped per SDM Vol 2A §2.1.1
    // "Instruction Prefixes" — they don't affect the MOV opcodes we decode.
    while (i < buf.len) {
        switch (buf[i]) {
            0x40...0x4F => {
                rex = buf[i];
                has_rex_w = (rex & 0x08) != 0;
                i += 1;
            },
            0x66 => {
                has_66 = true;
                i += 1;
            },
            // Address size, lock, rep, segment overrides -- skip
            0x67, 0xF0, 0xF2, 0xF3, 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65 => {
                i += 1;
            },
            else => break,
        }
    }

    if (i >= buf.len) return DecodeError.IncompleteDecode;
    const opcode = buf[i];
    i += 1;

    if (i >= buf.len) return DecodeError.IncompleteDecode;
    const modrm = buf[i];
    i += 1;

    // ModR/M decomposition — Intel SDM Vol 2A §2.1.5, Table 2-1
    // (32-bit addressing forms with the ModR/M byte) and Table 2-2
    // (addressing forms reference for SIB). Bits: mod[7:6] reg[5:3] r/m[2:0].
    const mod_field: u2 = @truncate(modrm >> 6);
    // REX.R extends ModR/M.reg (SDM Vol 2A §2.2.1 Table 2-4). REX is
    // bit 2 of the REX prefix byte.
    const reg_field: u4 = @as(u4, @truncate((modrm >> 3) & 7)) | (if (rex & 0x04 != 0) @as(u4, 8) else 0);
    const rm_field: u3 = @truncate(modrm & 7);

    // SIB byte present when mod != 11 AND r/m == 100 (SDM Vol 2A §2.1.5
    // Table 2-2 "32-Bit Addressing Forms with the SIB Byte"). Layout:
    // scale[7:6] index[5:3] base[2:0].
    var has_sib_disp32 = false;
    if (mod_field != 0b11 and rm_field == 0b100) {
        if (i >= buf.len) return DecodeError.IncompleteDecode;
        const sib = buf[i];
        i += 1; // SIB
        const sib_base: u3 = @truncate(sib & 7);
        // SIB base==101 combined with mod==00 replaces the base
        // register with an absolute disp32 (SDM Vol 2A §2.1.5,
        // footnote to Table 2-2).
        if (mod_field == 0b00 and sib_base == 0b101) {
            has_sib_disp32 = true;
        }
    }

    // Displacement size derived from ModR/M.mod (SDM Vol 2A Table 2-1)
    // and the SIB corner case. Special case: mod==00 r/m==101 is
    // RIP-relative disp32 in 64-bit mode (SDM Vol 2A §2.2.1.6).
    if (has_sib_disp32) {
        i += 4; // SIB base=101 + mod=00 -> absolute disp32
    } else if (mod_field == 0b00 and rm_field == 0b101) {
        i += 4; // RIP-relative disp32
    } else if (mod_field == 0b01) {
        i += 1; // disp8
    } else if (mod_field == 0b10) {
        i += 4; // disp32
    }

    if (i > buf.len) return DecodeError.IncompleteDecode;

    return switch (opcode) {
        // MOV r/m32, r32 -- write from register
        0x89 => if (has_rex_w) DecodeError.UnsupportedInstruction else MmioOp{
            .is_write = true,
            .size = if (has_66) 2 else 4,
            .reg = reg_field,
            .value = 0,
            .len = i,
            .is_immediate = false,
        },
        // MOV r32, r/m32 -- read to register
        0x8B => if (has_rex_w) DecodeError.UnsupportedInstruction else MmioOp{
            .is_write = false,
            .size = if (has_66) 2 else 4,
            .reg = reg_field,
            .value = 0,
            .len = i,
        },
        // MOV r/m8, imm8 -- write byte immediate
        0xC6 => blk: {
            if (i + 1 > buf.len) break :blk DecodeError.IncompleteDecode;
            const imm: u32 = buf[i];
            i += 1;
            break :blk MmioOp{
                .is_write = true,
                .size = 1,
                .reg = 0,
                .value = imm,
                .len = i,
                .is_immediate = true,
            };
        },
        // MOV r/m32, imm32 -- write immediate
        0xC7 => blk: {
            if (has_rex_w) break :blk DecodeError.UnsupportedInstruction;
            const imm_size: u8 = if (has_66) 2 else 4;
            if (i + imm_size > buf.len) break :blk DecodeError.IncompleteDecode;
            var imm: u32 = 0;
            if (imm_size >= 1) imm |= @as(u32, buf[i]);
            if (imm_size >= 2) imm |= @as(u32, buf[i + 1]) << 8;
            if (imm_size >= 3) imm |= @as(u32, buf[i + 2]) << 16;
            if (imm_size >= 4) imm |= @as(u32, buf[i + 3]) << 24;
            i += imm_size;
            break :blk MmioOp{
                .is_write = true,
                .size = imm_size,
                .reg = 0,
                .value = imm,
                .len = i,
                .is_immediate = true,
            };
        },
        // MOV r/m8, r8 -- write byte from register
        0x88 => MmioOp{
            .is_write = true,
            .size = 1,
            .reg = reg_field,
            .value = 0,
            .len = i,
            .is_immediate = false,
        },
        // MOV r8, r/m8 -- read byte to register
        0x8A => MmioOp{
            .is_write = false,
            .size = 1,
            .reg = reg_field,
            .value = 0,
            .len = i,
        },
        else => DecodeError.UnsupportedInstruction,
    };
}


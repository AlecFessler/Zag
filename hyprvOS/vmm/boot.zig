/// Linux boot protocol implementation.
/// Parses bzImage, builds boot_params (zero page), E820 memory map,
/// command line, and minimal ACPI tables for guest boot.

const log = @import("log.zig");
const mem = @import("mem.zig");

// Guest physical memory layout
pub const BOOT_PARAMS_ADDR: u64 = 0x10000;
pub const CMDLINE_ADDR: u64 = 0x20000;
pub const KERNEL_ADDR: u64 = 0x100000;
pub const INITRAMFS_ADDR: u64 = 0x1000000; // 16 MB
pub const ACPI_RSDP_ADDR: u64 = 0xE0000;
pub const ACPI_TABLE_ADDR: u64 = 0xE1000;

/// Parse bzImage and load the protected-mode kernel into guest memory.
pub fn loadBzImage(bzimage: []const u8) void {
    // setup_sects is at offset 0x1F1 (1 byte). If 0, treat as 4.
    const setup_sects: u32 = if (bzimage[0x1F1] == 0) 4 else @as(u32, bzimage[0x1F1]);
    const setup_size = (@as(usize, setup_sects) + 1) * 512;

    log.print("bzImage: setup_sects=");
    log.dec(setup_sects);
    log.print(", kernel offset=0x");
    log.hex32(@intCast(setup_size));
    log.print(", kernel size=");
    log.dec(bzimage.len - setup_size);
    log.print("\n");

    // Protected-mode kernel follows setup code
    if (setup_size >= bzimage.len) {
        log.print("bzImage: setup_size exceeds image!\n");
        return;
    }
    const pm_kernel = bzimage[setup_size..];
    mem.writeGuest(KERNEL_ADDR, pm_kernel);

    log.print("bzImage: loaded ");
    log.dec(pm_kernel.len);
    log.print(" bytes at guest phys 0x");
    log.hex64(KERNEL_ADDR);
    log.print("\n");
}

/// Load initramfs into guest memory.
pub fn loadInitramfs(initramfs: []const u8) void {
    mem.writeGuest(INITRAMFS_ADDR, initramfs);
    log.print("initramfs: loaded ");
    log.dec(initramfs.len);
    log.print(" bytes at 0x");
    log.hex64(INITRAMFS_ADDR);
    log.print("\n");
}

/// Build the boot_params (zero page) at guest phys 0x10000.
pub fn setupBootParams(bzimage: []const u8, initramfs_len: usize, ram_size: u64) void {
    var params: [4096]u8 = .{0} ** 4096;

    // Copy setup header from bzImage (offset 0x1F1 to ~0x268)
    const hdr_start: usize = 0x1F1;
    const hdr_end: usize = @min(0x268, bzimage.len);
    if (hdr_end > hdr_start) {
        @memcpy(params[hdr_start..hdr_end], bzimage[hdr_start..hdr_end]);
    }

    // type_of_loader = 0xFF (undefined bootloader)
    params[0x210] = 0xFF;

    // loadflags: set LOADED_HIGH (bit 0) + CAN_USE_HEAP (bit 7)
    // Preserve KEEP_SEGMENTS if already set, add our bits
    params[0x211] = params[0x211] | 0x01 | 0x80;

    // cmd_line_ptr (u32 at offset 0x228)
    writeU32(&params, 0x228, @intCast(CMDLINE_ADDR));

    // heap_end_ptr (u16 at offset 0x224)
    writeU16(&params, 0x224, 0xDE00);

    // ramdisk_image (u32 at offset 0x218)
    writeU32(&params, 0x218, @intCast(INITRAMFS_ADDR));

    // ramdisk_size (u32 at offset 0x21C)
    writeU32(&params, 0x21C, @intCast(initramfs_len));

    // vid_mode = 0xFFFF (normal mode)
    writeU16(&params, 0x1FA, 0xFFFF);

    // E820 memory map
    // e820_table at offset 0x2D0, each entry 20 bytes, max 128
    // e820_entries at offset 0x1E8 (u8)
    const e820_base: usize = 0x2D0;

    // Entry 0: 0 → 0x9FC00 (conventional memory, usable)
    writeE820(&params, e820_base + 0, 0x0, 0x9FC00, 1);

    // Entry 1: 0x9FC00 → 0xA0000 (EBDA, reserved)
    writeE820(&params, e820_base + 20, 0x9FC00, 0x400, 2);

    // Entry 2: 0xE0000 → 0x100000 (BIOS ROM + ACPI area, reserved)
    writeE820(&params, e820_base + 40, 0xE0000, 0x20000, 2);

    // Entry 3: 0x100000 → ram_size (usable)
    writeE820(&params, e820_base + 60, 0x100000, ram_size - 0x100000, 1);

    params[0x1E8] = 4; // e820_entries count

    // Write boot_params to guest memory
    mem.writeGuest(BOOT_PARAMS_ADDR, &params);
    log.print("boot_params: zero page at 0x");
    log.hex64(BOOT_PARAMS_ADDR);
    log.print(", cmdline at 0x");
    log.hex64(CMDLINE_ADDR);
    log.print("\n");
}

/// Build boot_params from a bzImage already loaded into guest memory at temp_addr.
/// Reads the setup header from the guest memory copy.
pub fn setupBootParamsFromGuest(temp_addr: u64, initramfs_size: u64, ram_size: u64) void {
    var params: [4096]u8 = .{0} ** 4096;

    // Copy setup header from guest memory (offset 0x1F1 in the bzImage)
    const hdr_start: usize = 0x1F1;
    const hdr_end: usize = 0x268;
    const guest_hdr = mem.readGuestSlice(temp_addr + hdr_start, hdr_end - hdr_start);
    @memcpy(params[hdr_start..hdr_end], guest_hdr);

    // type_of_loader = 0xFF
    params[0x210] = 0xFF;

    // loadflags: LOADED_HIGH + CAN_USE_HEAP
    params[0x211] = params[0x211] | 0x01 | 0x80;

    // cmd_line_ptr
    writeU32Buf(&params, 0x228, @intCast(CMDLINE_ADDR));

    // heap_end_ptr
    writeU16Buf(&params, 0x224, 0xDE00);

    // ramdisk_image
    writeU32Buf(&params, 0x218, @intCast(INITRAMFS_ADDR));

    // ramdisk_size
    writeU32Buf(&params, 0x21C, @intCast(initramfs_size));

    // vid_mode
    writeU16Buf(&params, 0x1FA, 0xFFFF);

    // E820 memory map
    const e820_base: usize = 0x2D0;
    writeE820(&params, e820_base + 0, 0x0, 0x9FC00, 1);
    writeE820(&params, e820_base + 20, 0x9FC00, 0x400, 2);
    writeE820(&params, e820_base + 40, 0xE0000, 0x20000, 2);
    writeE820(&params, e820_base + 60, 0x100000, ram_size - 0x100000, 1);
    params[0x1E8] = 4;

    mem.writeGuest(BOOT_PARAMS_ADDR, &params);
    log.print("boot_params: configured from guest memory\n");
}

/// Write command line to guest memory.
pub fn setupCmdline(cmdline: []const u8) void {
    mem.writeGuest(CMDLINE_ADDR, cmdline);
    // Null terminator
    const zero: [1]u8 = .{0};
    mem.writeGuest(CMDLINE_ADDR + cmdline.len, &zero);
}

/// Build minimal ACPI tables in guest memory.
/// Linux requires ACPI to boot on modern configs.
pub fn setupAcpiTables() void {
    // RSDP at 0xE0000 (scanned by Linux BIOS ROM area search)
    var rsdp: [36]u8 = .{0} ** 36;
    // Signature: "RSD PTR "
    @memcpy(rsdp[0..8], "RSD PTR ");
    // Revision: 2 (ACPI 2.0+ for XSDT)
    rsdp[15] = 2;
    // RSDT address (u32 at offset 16) — point to XSDT area
    writeU32Buf(&rsdp, 16, @intCast(ACPI_TABLE_ADDR));
    // Length (u32 at offset 20) — RSDP v2 is 36 bytes
    writeU32Buf(&rsdp, 20, 36);
    // XSDT address (u64 at offset 24)
    writeU64Buf(&rsdp, 24, ACPI_TABLE_ADDR);
    // OEM ID
    @memcpy(rsdp[9..15], "ZAGVMM");
    // Compute checksum for first 20 bytes (v1 checksum at offset 8)
    rsdp[8] = acpiChecksum(rsdp[0..20]);
    // Extended checksum for all 36 bytes (at offset 32)
    rsdp[32] = acpiChecksum(rsdp[0..36]);

    mem.writeGuest(ACPI_RSDP_ADDR, &rsdp);

    // Build tables at ACPI_TABLE_ADDR
    // Layout: XSDT | MADT | FADT | DSDT
    const xsdt_offset: u64 = 0;
    const madt_offset: u64 = 256; // leave room
    const fadt_offset: u64 = 512;
    const dsdt_offset: u64 = 768;

    var tables: [4096]u8 = .{0} ** 4096;

    // --- DSDT (minimal, just header) ---
    const dsdt_len: u32 = 36;
    buildAcpiHeader(tables[dsdt_offset..], "DSDT", dsdt_len, 2);

    // --- FADT ---
    const fadt_len: u32 = 116; // Minimal FADT for ACPI 2.0
    buildAcpiHeader(tables[fadt_offset..], "FACP", fadt_len, 5);
    // DSDT pointer (offset 40 in FADT)
    writeU32Buf(tables[fadt_offset..], 40, @intCast(ACPI_TABLE_ADDR + dsdt_offset));
    // Preferred PM profile (offset 45): unspecified
    tables[fadt_offset + 45] = 0;
    // SCI interrupt (offset 46): 9
    writeU16Buf(tables[fadt_offset..], 46, 9);
    // PM1a event block (offset 56, u32): fake address
    writeU32Buf(tables[fadt_offset..], 56, 0x400);
    // PM1a control block (offset 64, u32)
    writeU32Buf(tables[fadt_offset..], 64, 0x404);
    // PM1 event length (offset 88)
    tables[fadt_offset + 88] = 4;
    // PM1 control length (offset 89)
    tables[fadt_offset + 89] = 2;
    // FADT flags (offset 112, u32): WBINVD (bit 0) + HW_REDUCED_ACPI (bit 20)
    // HW_REDUCED_ACPI tells Linux not to try to access PM hardware
    writeU32Buf(tables[fadt_offset..], 112, (1 << 0) | (1 << 20));
    // X_DSDT (offset 140 in FADT 5.0+, u64) — only if fadt_len > 140
    // We keep it small, Linux will use the 32-bit DSDT pointer
    // Recompute FADT checksum
    tables[fadt_offset + 9] = acpiChecksum(tables[fadt_offset..][0..fadt_len]);

    // --- MADT ---
    const local_apic_size: u32 = 8; // type(1) + len(1) + proc_id(1) + apic_id(1) + flags(4)
    const io_apic_size: u32 = 12; // type(1) + len(1) + id(1) + reserved(1) + addr(4) + gsi_base(4)
    const madt_len: u32 = 44 + local_apic_size + io_apic_size;
    buildAcpiHeader(tables[madt_offset..], "APIC", madt_len, 3);
    // Local APIC address (offset 36, u32)
    writeU32Buf(tables[madt_offset..], 36, 0xFEE00000);
    // Flags (offset 40, u32): PCAT_COMPAT
    writeU32Buf(tables[madt_offset..], 40, 1);

    // Local APIC entry at offset 44
    var off: usize = 44;
    tables[madt_offset + off] = 0; // type = Processor Local APIC
    tables[madt_offset + off + 1] = 8; // length
    tables[madt_offset + off + 2] = 0; // ACPI processor ID
    tables[madt_offset + off + 3] = 0; // APIC ID
    writeU32Buf(tables[madt_offset + off..], 4, 1); // flags: enabled
    off += 8;

    // I/O APIC entry
    tables[madt_offset + off] = 1; // type = I/O APIC
    tables[madt_offset + off + 1] = 12; // length
    tables[madt_offset + off + 2] = 1; // I/O APIC ID
    tables[madt_offset + off + 3] = 0; // reserved
    writeU32Buf(tables[madt_offset + off..], 4, 0xFEC00000); // I/O APIC address
    writeU32Buf(tables[madt_offset + off..], 8, 0); // GSI base

    // Recompute MADT checksum
    tables[madt_offset + 9] = acpiChecksum(tables[madt_offset..][0..madt_len]);

    // --- XSDT ---
    // XSDT header (36 bytes) + 2 pointers (8 bytes each) = 52 bytes
    const xsdt_len: u32 = 36 + 2 * 8;
    buildAcpiHeader(tables[xsdt_offset..], "XSDT", xsdt_len, 1);
    // Entry 0: MADT
    writeU64Buf(tables[xsdt_offset..], 36, ACPI_TABLE_ADDR + madt_offset);
    // Entry 1: FADT
    writeU64Buf(tables[xsdt_offset..], 44, ACPI_TABLE_ADDR + fadt_offset);
    // Recompute XSDT checksum
    tables[xsdt_offset + 9] = acpiChecksum(tables[xsdt_offset..][0..xsdt_len]);

    // Also build a minimal RSDT for ACPI 1.0 compat
    // (the RSDP.rsdt_address already points to ACPI_TABLE_ADDR,
    //  but we wrote XSDT there. Patch RSDP rsdt_address to point
    //  somewhere else, or just let Linux use XSDT via revision 2.)
    // Linux prefers XSDT when revision >= 2, so this is fine.

    mem.writeGuest(ACPI_TABLE_ADDR, &tables);
    log.print("ACPI: RSDP at 0x");
    log.hex64(ACPI_RSDP_ADDR);
    log.print(", tables at 0x");
    log.hex64(ACPI_TABLE_ADDR);
    log.print("\n");
}

fn buildAcpiHeader(buf: []u8, sig: *const [4]u8, length: u32, revision: u8) void {
    @memcpy(buf[0..4], sig);
    writeU32Buf(buf, 4, length);
    buf[8] = revision;
    buf[9] = 0; // checksum placeholder
    @memcpy(buf[10..16], "ZAGVMM");
    @memcpy(buf[16..24], "ZAGKERML");
    writeU32Buf(buf, 24, 1); // OEM revision
    @memcpy(buf[28..32], "ZAG ");
    writeU32Buf(buf, 32, 1); // ASL compiler revision
}

fn acpiChecksum(data: []const u8) u8 {
    var sum: u8 = 0;
    for (data) |b| {
        sum +%= b;
    }
    return 0 -% sum;
}

fn writeE820(params: []u8, offset: usize, addr: u64, size: u64, type_: u32) void {
    writeU64Buf(params, offset, addr);
    writeU64Buf(params, offset + 8, size);
    writeU32Buf(params, offset + 16, type_);
}

fn writeU16(params: []u8, offset: usize, val: u16) void {
    writeU16Buf(params, offset, val);
}

fn writeU32(params: []u8, offset: usize, val: u32) void {
    writeU32Buf(params, offset, val);
}

fn writeU16Buf(buf: []u8, offset: usize, val: u16) void {
    @as(*align(1) u16, @ptrCast(buf.ptr + offset)).* = val;
}

fn writeU32Buf(buf: []u8, offset: usize, val: u32) void {
    @as(*align(1) u32, @ptrCast(buf.ptr + offset)).* = val;
}

fn writeU64Buf(buf: []u8, offset: usize, val: u64) void {
    @as(*align(1) u64, @ptrCast(buf.ptr + offset)).* = val;
}

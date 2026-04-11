/// Linux boot protocol implementation.
/// Parses bzImage, builds boot_params (zero page), E820 memory map,
/// and command line for guest boot. ACPI tables are in acpi.zig.

const log = @import("log.zig");
const mem = @import("mem.zig");

// Guest physical memory layout
pub const BOOT_PARAMS_ADDR: u64 = 0x10000;
pub const CMDLINE_ADDR: u64 = 0x20000;
pub const KERNEL_ADDR: u64 = 0x100000;
pub const INITRAMFS_ADDR: u64 = 0x6000000; // 96 MB — must be above kernel decompression zone

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

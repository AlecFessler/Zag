/// Guest physical memory management.
/// Allocates host virtual pages via vm_reserve and maps them into the
/// guest physical address space via guest_map.

const lib = @import("lib");

const log = @import("log.zig");
const syscall = lib.syscall;

const PAGE_SIZE: u64 = 4096;

var host_base: u64 = 0;
var mapped_size: u64 = 0;

/// Allocate and map guest physical memory.
/// Creates a contiguous host virtual region and maps it 1:1 into guest
/// physical address space starting at guest phys 0.
pub fn setupGuestMemory(size: u64) void {
    // rights = 0x7 (read + write + execute) — we need execute for guest code pages
    const result = syscall.vm_reserve(0, size, 0x7);
    if (result.val < 0) {
        log.print("mem: vm_reserve failed: ");
        log.dec(@as(u64, @bitCast(-result.val)));
        log.print("\n");
        syscall.shutdown();
    }
    host_base = result.val2;
    mapped_size = size;

    log.print("mem: reserved ");
    log.dec(size / (1024 * 1024));
    log.print(" MB at host 0x");
    log.hex64(host_base);
    log.print("\n");

    // Map into guest physical address space.
    // guest_map supports multi-page sizes, so map the whole thing at once.
    const mr = syscall.guest_map(host_base, 0, size, 0x7);
    if (mr != syscall.E_OK) {
        log.print("mem: guest_map failed: ");
        log.dec(@as(u64, @bitCast(-mr)));
        log.print("\n");
        syscall.shutdown();
    }

    log.print("mem: mapped guest phys 0x0 - 0x");
    log.hex64(size);
    log.print("\n");
}

/// Write data to guest physical memory via the host mapping.
pub fn writeGuest(guest_phys: u64, data: []const u8) void {
    if (guest_phys + data.len > mapped_size) {
        log.print("mem: writeGuest out of bounds at 0x");
        log.hex64(guest_phys);
        log.print("\n");
        return;
    }
    const dst: [*]u8 = @ptrFromInt(host_base + guest_phys);
    @memcpy(dst[0..data.len], data);
}

/// Read a single byte from guest physical memory.
pub fn readGuestByte(guest_phys: u64) u8 {
    if (guest_phys >= mapped_size) return 0;
    const ptr: *const u8 = @ptrFromInt(host_base + guest_phys);
    return ptr.*;
}

/// Get a slice of guest physical memory.
pub fn readGuestSlice(guest_phys: u64, len: usize) []const u8 {
    const ptr: [*]const u8 = @ptrFromInt(host_base + guest_phys);
    return ptr[0..len];
}

/// Copy data within guest physical memory (non-overlapping regions only).
pub fn copyGuest(dst_phys: u64, src_phys: u64, len: u64) void {
    if (dst_phys + len > mapped_size or src_phys + len > mapped_size) return;
    const dst: [*]u8 = @ptrFromInt(host_base + dst_phys);
    const src: [*]const u8 = @ptrFromInt(host_base + src_phys);
    @memcpy(dst[0..@intCast(len)], src[0..@intCast(len)]);
}

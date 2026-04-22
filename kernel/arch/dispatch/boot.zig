const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const PAddr = zag.memory.address.PAddr;

pub fn init() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.init.init(),
        .aarch64 => aarch64.init.init(),
        else => unreachable,
    }
}

pub fn parseFirmwareTables(xsdp_paddr: PAddr) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.acpi.parseAcpi(xsdp_paddr),
        .aarch64 => try aarch64.acpi.parseAcpi(xsdp_paddr),
        else => unreachable,
    }
}

/// Synchronize the instruction cache with the data cache after writing
/// new executable code to memory. On x86-64 this is a no-op (coherent
/// I-cache). On aarch64 the I/D caches are separate and loader code must
/// explicitly invalidate the I-cache before fetching freshly written
/// instructions, or stale bytes can be decoded as garbage.
pub fn syncInstructionCache() void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => asm volatile (
            \\ic ialluis
            \\dsb ish
            \\isb
            ::: .{ .memory = true }),
        else => unreachable,
    }
}

/// Clean the data cache over the given byte range to the Point of
/// Unification. On x86-64 this is a no-op (coherent caches). On aarch64
/// this is required after writing freshly loaded ELF code through the
/// physmap (D-cache) view: until the lines are pushed past the unified
/// PoU, a subsequent `ic ivau`/`ic ialluis` cannot make the new
/// instruction bytes visible to instruction fetch, and the user's
/// entry point fetches stale (typically zero) bytes — manifesting as
/// repeating instruction-abort exceptions on every ERET.
///
/// ARM ARM B2.4.6 / D5.10.2: data-to-instruction cache coherency.
pub fn cleanDcacheToPou(start: u64, len: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => {
            if (len == 0) return;
            // Conservative 64-byte cache line for Cortex-A72/A76. The
            // exact line size is in CTR_EL0.DminLine; using 64 bytes
            // simply over-cleans on cores with smaller lines, which is
            // safe.
            const line: u64 = 64;
            const end = start + len;
            var addr = start & ~(line - 1);
            while (addr < end) : (addr += line) {
                asm volatile ("dc cvau, %[a]"
                    :
                    : [a] "r" (addr),
                    : .{ .memory = true });
            }
            asm volatile ("dsb ish" ::: .{ .memory = true });
        },
        else => unreachable,
    }
}

/// Clean + invalidate the data cache over the given byte range to the
/// point of coherency. On x86-64 this is a no-op (coherent D-cache). On
/// aarch64 this is required when memory is reconfigured from Normal
/// Non-cacheable to Normal Write-Back (e.g., when the kernel installs
/// its own MAIR_EL1 over UEFI's), otherwise stale cache lines from a
/// prior cacheable view can shadow freshly written NC data.
pub fn cleanInvalidateDcacheRange(start: u64, len: u64) void {
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => {
            // Drain any pending Normal Non-cacheable stores from the
            // write buffer to RAM before we start cleaning the cache.
            // Without this, NC writes may still be in flight when DC
            // CIVAC runs, and subsequent WB reads can race past the
            // pending writes.
            asm volatile ("dsb sy" ::: .{ .memory = true });
            // 64-byte cache line on Cortex-A72. Use a conservative
            // fixed line size rather than reading CTR_EL0 here.
            const line: u64 = 64;
            const end = start + len;
            var addr = start & ~(line - 1);
            while (addr < end) : (addr += line) {
                asm volatile ("dc civac, %[a]"
                    :
                    : [a] "r" (addr),
                    : .{ .memory = true });
            }
            asm volatile (
                \\dsb sy
                \\isb
                ::: .{ .memory = true });
        },
        else => unreachable,
    }
}

pub fn print(
    comptime format: []const u8,
    args: anytype,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.serial.print(format, args),
        .aarch64 => aarch64.serial.print(format, args),
        else => unreachable,
    }
}

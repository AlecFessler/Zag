//! GDT and TSS setup for x86-64.
//!
//! Defines the kernel and user segment descriptors, constructs the GDT,
//! installs a TSS, and loads them via `lgdt`/`ltr`. Used during early bring-up
//! and whenever the bootstrap CPU’s stack selector (`rsp0`) must be updated.

const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const paging = @import("paging.zig");
const std = @import("std");

const VAddr = paging.VAddr;

/// GDTR pointer used by `lgdt`.
pub const GdtPtr = packed struct {
    /// Size of GDT in bytes minus 1 (hardware format).
    limit: u16,
    /// Linear base address of the GDT.
    base: u64,
};

/// 64-bit Task State Segment (minimal fields used by the kernel).
///
/// Only `rsp0` and IST slots are used here; I/O bitmap is placed past the TSS
/// and disabled by setting `iomap_base` to `@sizeOf(Tss)`.
pub const Tss = packed struct {
    reserved_0: u32 = 0,
    /// Ring-0 stack pointer loaded on privilege transition.
    rsp0: u64 = 0,
    rsp1: u64 = 0,
    rsp2: u64 = 0,
    reserved_1: u64 = 0,
    /// Interrupt Stack Table entries (optional per-vector stacks).
    ist1: u64 = 0,
    ist2: u64 = 0,
    ist3: u64 = 0,
    ist4: u64 = 0,
    ist5: u64 = 0,
    ist6: u64 = 0,
    ist7: u64 = 0,
    reserved_2: u64 = 0,
    reserved_3: u16 = 0,
    /// Offset to I/O bitmap (disabled when equal to `sizeof(Tss)`).
    iomap_base: u16 = @sizeOf(@This()),
};

/// Raw GDT entry layout (code/data/system). Internal use.
const GdtEntry = packed struct {
    limit_low: u16,
    base_low: u24,
    accessed: bool,
    read_write: bool,
    direction_confirming: bool,
    executable: bool,
    descriptor: bool,
    /// Descriptor privilege level.
    privilege: idt.PrivilegeLevel,
    present: bool,
    limit_high: u4,
    reserved_0: u1 = 0,
    /// L-bit (64-bit code) for code segments; 0 for data/system.
    is_64_bit: bool,
    /// D-bit (default operand size 32) for 32-bit code; 0 for 64-bit.
    is_32_bit: bool,
    /// Granularity (1 = 4KiB blocks, 0 = byte granularity).
    granularity: u1,
    base_high: u8,
};

/// Selector (offset) for kernel code segment.
pub const KERNEL_CODE_OFFSET: u16 = 0x08;
/// Selector (offset) for kernel data segment.
pub const KERNEL_DATA_OFFSET: u16 = 0x10;

/// Predefined kernel 64-bit code segment descriptor (RX).
pub const KERNEL_SEGMENT_CODE: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = true,
    .direction_confirming = false,
    .executable = true,
    .descriptor = true,
    .privilege = .ring_0,
    .present = true,
    .limit_high = 0,
    .reserved_0 = 0,
    .is_64_bit = true,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

/// Predefined kernel data segment descriptor (RW).
pub const KERNEL_SEGMENT_DATA: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = true,
    .direction_confirming = false,
    .executable = false,
    .descriptor = true,
    .privilege = .ring_0,
    .present = true,
    .limit_high = 0,
    .reserved_0 = 0,
    .is_64_bit = false,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

/// Selector for the null descriptor (must be present at index 0).
pub const NULL_OFFSET: u16 = 0x00;

/// Null descriptor placeholder.
pub const NULL_SEGMENT: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = false,
    .direction_confirming = false,
    .executable = false,
    .descriptor = false,
    .privilege = .ring_0,
    .present = false,
    .limit_high = 0,
    .reserved_0 = 0,
    .is_64_bit = false,
    .is_32_bit = false,
    .granularity = 0,
    .base_high = 0,
};

/// Selector for the TSS system descriptor (low entry; spans two slots).
pub const TSS_OFFSET: u16 = 0x28;
/// Selector for user code segment.
pub const USER_CODE_OFFSET: u16 = 0x18;
/// Selector for user data segment.
pub const USER_DATA_OFFSET: u16 = 0x20;

/// Predefined user 64-bit code segment descriptor (RX, DPL=3).
pub const USER_SEGMENT_CODE: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = true,
    .direction_confirming = false,
    .executable = true,
    .descriptor = true,
    .privilege = .ring_3,
    .present = true,
    .limit_high = 0,
    .reserved_0 = 0,
    .is_64_bit = true,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

/// Predefined user data segment descriptor (RW, DPL=3).
pub const USER_SEGMENT_DATA: GdtEntry = .{
    .limit_low = 0,
    .base_low = 0,
    .accessed = false,
    .read_write = true,
    .direction_confirming = false,
    .executable = false,
    .descriptor = true,
    .privilege = .ring_3,
    .present = true,
    .limit_high = 0,
    .reserved_0 = 0,
    .is_64_bit = false,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

/// Number of GDT entries used (including TSS high slot).
const NUM_GDT_ENTRIES: u16 = 7;
/// GDTR.limit value computed from entry count.
const TABLE_SIZE: u16 = @sizeOf(GdtEntry) * NUM_GDT_ENTRIES - 1;

/// Global GDT table (fixed order).
///
/// Index layout:
/// 0: null, 1: kernel code, 2: kernel data, 3: user code, 4: user data,
/// 5: TSS (low descriptor), 6: TSS (high dword).
pub var gdt_entries: [7]GdtEntry = blk: {
    var tmp: [7]GdtEntry = undefined;
    tmp[0] = NULL_SEGMENT;
    tmp[1] = KERNEL_SEGMENT_CODE;
    tmp[2] = KERNEL_SEGMENT_DATA;
    tmp[3] = USER_SEGMENT_CODE;
    tmp[4] = USER_SEGMENT_DATA;
    tmp[5] = NULL_SEGMENT;
    tmp[6] = NULL_SEGMENT;
    break :blk tmp;
};

/// Current GDTR contents used by `lgdt`.
pub var gdt_ptr: GdtPtr = .{
    .limit = TABLE_SIZE,
    .base = 0,
};

/// Primary TSS used by the bootstrap CPU.
pub var main_tss_entry: Tss = .{};

/// Initializes GDT/TSS and loads them.
///
/// Arguments:
/// - `kernel_stack_top`: ring-0 stack pointer stored in `TSS.rsp0`
pub fn init(kernel_stack_top: VAddr) void {
    main_tss_entry = .{};
    main_tss_entry.rsp0 = kernel_stack_top.addr;

    writeTssDescriptor(&main_tss_entry);

    gdt_ptr.base = @intFromPtr(&gdt_entries[0]);

    lgdt(&gdt_ptr);
    cpu.reloadSegments();
    ltr(TSS_OFFSET);
}

/// Loads GDTR from `p`.
///
/// Arguments:
/// - `p`: pointer to `GdtPtr` structure to load.
fn lgdt(p: *const GdtPtr) void {
    asm volatile ("lgdt (%[p])"
        :
        : [p] "r" (p),
        : .{ .memory = true });
}

/// Loads TR with selector `sel` (must reference a valid TSS descriptor).
///
/// Arguments:
/// - `sel`: selector to load into TR (offset of the TSS descriptor).
fn ltr(sel: u16) void {
    asm volatile (
        \\mov %[s], %%ax
        \\ltr %%ax
        :
        : [s] "ir" (sel),
        : .{});
}

/// Writes a 64-bit TSS descriptor (low+high) into the GDT at `TSS_OFFSET`.
///
/// Arguments:
/// - `tss_ptr`: pointer to the TSS whose descriptor should be written.
///
/// Notes:
/// - Populates the system descriptor fields, sets `present=1`, and stores the
///   high 32 bits of the base in the following GDT slot.
fn writeTssDescriptor(tss_ptr: *Tss) void {
    const base: u64 = @intFromPtr(tss_ptr);
    const limit: u20 = @truncate(@sizeOf(Tss) - 1);

    const tss_low_idx: u64 = @intCast((TSS_OFFSET >> 3));
    const tss_high_idx: u64 = tss_low_idx + 1;

    var low: GdtEntry = NULL_SEGMENT;
    low.limit_low = @truncate(limit);
    low.limit_high = @truncate(limit >> 16);
    low.base_low = @truncate(base);
    low.base_high = @truncate(base >> 24);
    low.accessed = true;              // type=0b1001 (available 64-bit TSS), modeled via fields
    low.read_write = false;
    low.direction_confirming = false;
    low.executable = true;            // “executable” bit contributes to system type encoding here
    low.descriptor = false;           // system descriptor (not code/data)
    low.privilege = .ring_0;
    low.present = true;
    low.is_64_bit = false;
    low.is_32_bit = false;
    low.granularity = 0;

    gdt_entries[tss_low_idx] = low;

    const raw: *[NUM_GDT_ENTRIES]u64 = @ptrCast(&gdt_entries);
    raw[tss_high_idx] = base >> 32;
}

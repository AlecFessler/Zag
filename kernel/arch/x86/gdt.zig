const cpu = @import("cpu.zig");
const idt = @import("idt.zig");
const paging = @import("paging.zig");
const std = @import("std");

const VAddr = paging.VAddr;

pub const GdtPtr = packed struct {
    limit: u16,
    base: u64,
};

pub const Tss = packed struct {
    reserved_0: u32 = 0,
    rsp0: u64 = 0,
    rsp1: u64 = 0,
    rsp2: u64 = 0,
    reserved_1: u64 = 0,
    ist1: u64 = 0,
    ist2: u64 = 0,
    ist3: u64 = 0,
    ist4: u64 = 0,
    ist5: u64 = 0,
    ist6: u64 = 0,
    ist7: u64 = 0,
    reserved_2: u64 = 0,
    reserved_3: u16 = 0,
    iomap_base: u16 = @sizeOf(@This()),
};

const GdtEntry = packed struct {
    limit_low: u16,
    base_low: u24,
    accessed: bool,
    read_write: bool,
    direction_confirming: bool,
    executable: bool,
    descriptor: bool,
    privilege: idt.PrivilegeLevel,
    present: bool,
    limit_high: u4,
    reserved_0: u1 = 0,
    is_64_bit: bool,
    is_32_bit: bool,
    granularity: u1,
    base_high: u8,
};

pub const KERNEL_CODE_OFFSET: u16 = 0x08;
pub const KERNEL_DATA_OFFSET: u16 = 0x10;
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
pub const NULL_OFFSET: u16 = 0x00;
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
pub const TSS_OFFSET: u16 = 0x28;
pub const USER_CODE_OFFSET: u16 = 0x18;
pub const USER_DATA_OFFSET: u16 = 0x20;
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

const NUM_GDT_ENTRIES: u16 = 7;
const TABLE_SIZE: u16 = @sizeOf(GdtEntry) * NUM_GDT_ENTRIES - 1;

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

pub var gdt_ptr: GdtPtr = .{
    .limit = TABLE_SIZE,
    .base = 0,
};

pub var main_tss_entry: Tss = .{};

pub fn init(kernel_stack_top: VAddr) void {
    main_tss_entry = .{};
    main_tss_entry.rsp0 = kernel_stack_top.addr;

    writeTssDescriptor(&main_tss_entry);

    gdt_ptr.base = @intFromPtr(&gdt_entries[0]);

    lgdt(&gdt_ptr);
    cpu.reloadSegments();
    ltr(TSS_OFFSET);
}

fn lgdt(p: *const GdtPtr) void {
    asm volatile ("lgdt (%[p])"
        :
        : [p] "r" (p),
        : .{ .memory = true });
}

fn ltr(sel: u16) void {
    asm volatile (
        \\mov %[s], %%ax
        \\ltr %%ax
        :
        : [s] "ir" (sel),
        : .{});
}

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
    low.accessed = true;
    low.read_write = false;
    low.direction_confirming = false;
    low.executable = true;
    low.descriptor = false;
    low.privilege = .ring_0;
    low.present = true;
    low.is_64_bit = false;
    low.is_32_bit = false;
    low.granularity = 0;

    gdt_entries[tss_low_idx] = low;

    const raw: *[NUM_GDT_ENTRIES]u64 = @ptrCast(&gdt_entries);
    raw[tss_high_idx] = base >> 32;
}

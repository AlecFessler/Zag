const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;

const PrivilegeLevel = zag.arch.x64.cpu.PrivilegeLevel;

const GdtPtr = packed struct {
    limit: u16,
    base: u64,
};

pub const Tss = packed struct {
    _res0: u32 = 0,
    rsp0: u64 = 0,
    rsp1: u64 = 0,
    rsp2: u64 = 0,
    _res1: u64 = 0,
    ist1: u64 = 0,
    ist2: u64 = 0,
    ist3: u64 = 0,
    ist4: u64 = 0,
    ist5: u64 = 0,
    ist6: u64 = 0,
    ist7: u64 = 0,
    _res2: u64 = 0,
    _res3: u16 = 0,
    iomap_base: u16 = @sizeOf(@This()),
};

const GdtEntry = packed struct(u64) {
    limit_low: u16,
    base_low: u24,
    accessed: bool,
    read_write: bool,
    direction_confirming: bool,
    executable: bool,
    descriptor: bool,
    privilege: PrivilegeLevel,
    present: bool,
    limit_high: u4,
    _res0: u1 = 0,
    is_64_bit: bool,
    is_32_bit: bool,
    granularity: u1,
    base_high: u8,
};

pub const NULL_OFFSET: u16 = 0x00;
pub const KERNEL_CODE_OFFSET: u16 = 0x08;
pub const KERNEL_DATA_OFFSET: u16 = 0x10;
pub const USER_CODE_OFFSET: u16 = 0x18;
pub const USER_DATA_OFFSET: u16 = 0x20;
pub const TSS_OFFSET: u16 = 0x28;

const NULL_SEGMENT: GdtEntry = .{
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
    ._res0 = 0,
    .is_64_bit = false,
    .is_32_bit = false,
    .granularity = 0,
    .base_high = 0,
};

const KERNEL_SEGMENT_CODE: GdtEntry = .{
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
    ._res0 = 0,
    .is_64_bit = true,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

const KERNEL_SEGMENT_DATA: GdtEntry = .{
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
    ._res0 = 0,
    .is_64_bit = false,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

const USER_SEGMENT_CODE: GdtEntry = .{
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
    ._res0 = 0,
    .is_64_bit = true,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

const USER_SEGMENT_DATA: GdtEntry = .{
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
    ._res0 = 0,
    .is_64_bit = false,
    .is_32_bit = false,
    .granularity = 1,
    .base_high = 0,
};

const MAX_CORES = 64;
const NUM_GDT_ENTRIES: u16 = 7;
const TABLE_SIZE: u16 = @sizeOf(GdtEntry) * NUM_GDT_ENTRIES - 1;

const base_gdt_entries: [7]GdtEntry = blk: {
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

var tss_entries: [MAX_CORES]Tss = [_]Tss{.{}} ** MAX_CORES;
var per_core_gdts: [MAX_CORES][7]GdtEntry = [_][7]GdtEntry{base_gdt_entries} ** MAX_CORES;
var per_core_gdt_ptrs: [MAX_CORES]GdtPtr = [_]GdtPtr{.{ .limit = TABLE_SIZE, .base = 0 }} ** MAX_CORES;

pub fn init() void {
    initForCore(0);
    loadGdt(0);
    reloadSegments();
    cpu.ltr(TSS_OFFSET);
}

pub fn initForCore(core_id: u64) void {
    tss_entries[core_id] = .{};
    writeTssDescriptor(core_id);
    per_core_gdt_ptrs[core_id].base = @intFromPtr(&per_core_gdts[core_id]);
}

pub fn loadGdt(core_id: u64) void {
    cpu.lgdt(&per_core_gdt_ptrs[core_id]);
}

pub fn coreTss(core_id: u64) *Tss {
    return &tss_entries[core_id];
}

pub fn reloadSegments() void {
    asm volatile (
        \\pushq %[cs_sel]
        \\leaq 1f(%%rip), %%rax
        \\pushq %%rax
        \\lretq
        \\1:
        \\movw %[ds_sel], %%ax
        \\movw %%ax, %%ds
        \\movw %%ax, %%es
        \\movw %%ax, %%ss
        :
        : [cs_sel] "i" (KERNEL_CODE_OFFSET),
          [ds_sel] "i" (KERNEL_DATA_OFFSET),
        : .{ .rax = true, .ax = true, .memory = true }
    );
}

fn writeTssDescriptor(core_id: u64) void {
    const base: u64 = @intFromPtr(&tss_entries[core_id]);
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

    per_core_gdts[core_id][tss_low_idx] = low;

    const raw: *[7]u64 = @ptrCast(&per_core_gdts[core_id]);
    raw[tss_high_idx] = base >> 32;
}

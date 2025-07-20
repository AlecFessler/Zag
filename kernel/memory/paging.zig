const std = @import("std");

const allocator_interface = @import("allocator.zig");
const Allocator = allocator_interface.Allocator;

const page_size = 4096;

pub const RW = enum(u1) { Readonly, ReadWrite };
pub const User = enum(u1) { User, Supervisor };

const PageEntry = packed struct {
    present: bool, // bit 0
    rw: RW, // bit 1
    user: User, // bit 2
    write_through: bool, // bit 3
    cache_disable: bool, // bit 4
    accessed: bool, // bit 5
    dirty: bool, // bit 6 (only meaningful in PTEs)
    huge_page: bool, // bit 7 (used as PAT in PTEs, page size in PDE/PDPTE)
    global: bool, // bit 8 (only in PTEs)
    ignored: u3, // bits 9–11
    addr: u40, // bits 12–51: physical address of next-level table or page
    reserved: u11, // bits 52–62: OS-reserved or must-be-zero depending on context
    nx: bool, // bit 63: no-execute (only if NX is supported/enabled)

    pub fn getPaddr(self: *PageEntry) u40 {
        return @as(u40, self.addr) << 12;
    }

    pub fn setPaddr(self: *PageEntry, addr: u40) void {
        self.addr = @as(u40, addr >> 12);
    }
};

comptime {
    std.debug.assert(@sizeOf(PageEntry) == 8);
}

const PML4Entry = PageEntry;
const PDPTEntry = PageEntry;
const PDEntry = PageEntry;
const PTEntry = PageEntry;

fn pml4_index(vaddr: usize) u9 {
    return @truncate(vaddr >> 39);
}

fn pdpt_index(vaddr: usize) u9 {
    return @truncate(vaddr >> 30);
}

fn pd_index(vaddr: usize) u9 {
    return @truncate(vaddr >> 21);
}

fn pt_index(vaddr: usize) u9 {
    return @truncate(vaddr >> 12);
}

pub fn read_cr3() usize {
    var value: usize = 0;
    asm volatile ("mov cr3, %[out]"
        : [out] "=r" (value),
    );
    return value;
}

pub fn mapPage(pml4: [*]PML4Entry, paddr: usize, vaddr: usize, rw: RW, user: User, allocator: *Allocator) void {
    std.debug.assert(std.mem.isAligned(paddr, page_size));
    std.debug.assert(std.mem.isAligned(vaddr, page_size));

    const flags = PageEntry{
        .present = true,
        .rw = rw,
        .user = user,
        .write_through = false,
        .cache_disable = false,
        .accessed = false,
        .dirty = false,
        .huge_page = false,
        .global = false,
        .ignored = 0,
        .addr = 0,
        .reserved = 0,
        .nx = false,
    };

    const pml4_idx = pml4_index(vaddr);
    const pdpt_idx = pdpt_index(vaddr);
    const pd_idx = pd_index(vaddr);
    const pt_idx = pt_index(vaddr);

    var pdpt_entry = &pml4[pml4_idx];
    if (!pdpt_entry.present) {
        const new_pdpt: [*]PDPTEntry = @alignCast(@ptrCast(allocator.alloc(page_size, page_size)));
        pdpt_entry.* = flags;
        pdpt_entry.setPaddr(@intCast(@intFromPtr(new_pdpt)));
    }
    const pdpt: [*]PDPTEntry = @ptrFromInt(pdpt_entry.getPaddr());

    var pd_entry = &pdpt[pdpt_idx];
    if (!pd_entry.present) {
        const new_pd: [*]PDEntry = @alignCast(@ptrCast(allocator.alloc(page_size, page_size)));
        pd_entry.* = flags;
        pd_entry.setPaddr(@intCast(@intFromPtr(new_pd)));
    }
    const pd: [*]PDEntry = @ptrFromInt(pd_entry.getPaddr());

    var pt_entry = &pd[pd_idx];
    if (!pt_entry.present) {
        const new_pt: [*]PTEntry = @alignCast(@ptrCast(allocator.alloc(page_size, page_size)));
        pt_entry.* = flags;
        pt_entry.setPaddr(@intCast(@intFromPtr(new_pt)));
    }
    const pt: [*]PTEntry = @ptrFromInt(pt_entry.getPaddr());

    pt[pt_idx] = flags;
    pt[pt_idx].setPaddr(@intCast(paddr));
}

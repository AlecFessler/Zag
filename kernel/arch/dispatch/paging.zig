const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const x64 = zag.arch.x64;

const MappingKind = zag.memory.address.MappingKind;
const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const Range = zag.utils.range.Range;
const VAddr = zag.memory.address.VAddr;
const VarPageSize = zag.capdom.var_range.PageSize;
const VarCacheType = zag.capdom.var_range.CacheType;

// ── Address Space Layout ────────────────────────────────────────────────
// Architecture-specific virtual address space boundaries. These define
// the user/kernel split, physmap location, and kernel code range.

pub const addr_space = switch (builtin.cpu.arch) {
    .x86_64 => struct {
        pub const user: Range = .{
            .start = 0x0000_0000_0000_0000,
            .end = 0xFFFF_8000_0000_0000,
        };
        pub const kernel: Range = .{
            .start = 0xFFFF_8000_0000_0000,
            .end = 0xFFFF_8400_0000_0000,
        };
        pub const physmap: Range = .{
            .start = 0xFFFF_FF80_0000_0000,
            .end = 0xFFFF_FF88_0000_0000,
        };
        pub const kernel_code: Range = .{
            .start = 0xFFFF_FFFF_8000_0000,
            .end = 0xFFFF_FFFF_C000_0000,
        };
    },
    .aarch64 => struct {
        pub const user: Range = .{
            .start = 0x0000_0000_0000_0000,
            .end = 0x0001_0000_0000_0000,
        };
        // Kernel heap/data (above kernel_code).
        pub const kernel: Range = .{
            .start = 0xFFFF_0000_4000_0000,
            .end = 0xFFFF_0400_0000_0000,
        };
        pub const physmap: Range = .{
            .start = 0xFFFF_FF80_0000_0000,
            .end = 0xFFFF_FF88_0000_0000,
        };
        // Kernel text/rodata (bottom of TTBR1 range).
        pub const kernel_code: Range = .{
            .start = 0xFFFF_0000_0000_0000,
            .end = 0xFFFF_0000_4000_0000,
        };
    },
    else => unreachable,
};

/// NULL guard at the bottom of every user address space. The first
/// page must always fault — no mapping path may install a leaf into
/// `[0, 0x1000)`. Spec §[address_space].
pub const user_null_guard: Range = .{
    .start = 0x0000_0000_0000_0000,
    .end = 0x0000_0000_0000_1000,
};

/// ASLR zone — kernel-chosen base, randomized at placement time. Used
/// for ELF segments, EC stacks, and `create_var(preferred_base = 0)`.
/// Spec §[address_space].
pub const user_aslr: Range = switch (builtin.cpu.arch) {
    .x86_64 => .{
        .start = 0x0000_0000_0000_1000,
        .end = 0x0000_1000_0000_0000,
    },
    .aarch64 => .{
        .start = 0x0000_0000_0000_1000,
        .end = 0x0000_1000_0000_0000,
    },
    else => unreachable,
};

/// Static zone — userspace-chosen base via `create_var(preferred_base
/// != 0)`. Placement is deterministic. Spec §[address_space].
pub const user_static: Range = switch (builtin.cpu.arch) {
    .x86_64 => .{
        .start = 0x0000_1000_0000_0000,
        .end = 0x0000_8000_0000_0000,
    },
    .aarch64 => .{
        .start = 0x0000_1000_0000_0000,
        .end = 0x0001_0000_0000_0000,
    },
    else => unreachable,
};

pub fn mapPage(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    perms: MemoryPerms,
    kind: MappingKind,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.paging.mapPage(addr_space_root, phys, virt, perms, kind),
        .aarch64 => try aarch64.paging.mapPage(addr_space_root, phys, virt, perms, kind),
        else => unreachable,
    }
}

pub fn mapPageBoot(
    addr_space_root: VAddr,
    phys: PAddr,
    virt: VAddr,
    size: PageSize,
    perms: MemoryPerms,
    kind: MappingKind,
    allocator: std.mem.Allocator,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.paging.mapPageBoot(addr_space_root, phys, virt, size, perms, kind, allocator),
        .aarch64 => try aarch64.paging.mapPageBoot(addr_space_root, phys, virt, size, perms, kind, allocator),
        else => unreachable,
    }
}

pub fn unmapPage(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.paging.unmapPage(addr_space_root, virt),
        .aarch64 => return aarch64.paging.unmapPage(addr_space_root, virt),
        else => unreachable,
    }
}

pub fn updatePagePerms(
    addr_space_root: PAddr,
    virt: VAddr,
    new_perms: MemoryPerms,
    kind: MappingKind,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.updatePagePerms(addr_space_root, virt, new_perms, kind),
        .aarch64 => aarch64.paging.updatePagePerms(addr_space_root, virt, new_perms, kind),
        else => unreachable,
    }
}

pub fn resolveVaddr(
    addr_space_root: PAddr,
    virt: VAddr,
) ?PAddr {
    switch (builtin.cpu.arch) {
        .x86_64 => return x64.paging.resolveVaddr(addr_space_root, virt),
        .aarch64 => return aarch64.paging.resolveVaddr(addr_space_root, virt),
        else => unreachable,
    }
}

/// Allocate a per-process address-space identifier for TLB tagging
/// (PCID on x86-64, ASID on aarch64). Returns null on exhaustion.
pub fn allocAddrSpaceId() ?u16 {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.pcid.allocate(),
        .aarch64 => aarch64.asid.allocate(),
        else => unreachable,
    };
}

/// Release an address-space identifier previously returned by
/// `allocAddrSpaceId`. The allocator invalidates every TLB entry tagged
/// with `id` before returning the slot so a future re-allocation does not
/// inherit stale mappings from the previous owner. Releasing id 0 is a
/// programming error.
pub fn freeAddrSpaceId(id: u16) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.pcid.free(id),
        .aarch64 => aarch64.asid.free(id),
        else => unreachable,
    }
}

/// Whether the kernel page table root is the same as the user table.
/// On x86-64 (single CR3) the bootloader must copy the UEFI identity map
/// into the new kernel table. On aarch64 (split TTBR0/TTBR1) the kernel
/// table is independent and should start clean.
pub const kernel_shares_user_table: bool = switch (builtin.cpu.arch) {
    .x86_64 => true,
    .aarch64 => false,
    else => unreachable,
};

/// Return the physical address of the kernel page table root.
/// On x86-64 this is the same as getAddrSpaceRoot() since CR3 covers both
/// halves. On aarch64 this reads TTBR1_EL1 (upper/kernel VA range).
pub fn getKernelAddrSpaceRoot() PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.getAddrSpaceRoot(),
        .aarch64 => aarch64.paging.getKernelAddrSpaceRoot(),
        else => unreachable,
    };
}

/// Set the kernel page table root. Bootloader-only — runs before
/// CR4.PCIDE is enabled, so on x86-64 the CR3 source operand cannot
/// carry the PCID/no-flush bits that runtime swapAddrSpace uses.
/// On aarch64 this writes TTBR1_EL1 (upper/kernel VA range).
pub fn setKernelAddrSpace(root: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.setKernelAddrSpace(root),
        .aarch64 => aarch64.paging.setKernelAddrSpace(root),
        else => unreachable,
    }
}

pub fn freeUserAddrSpace(addr_space_root: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.freeUserAddrSpace(addr_space_root),
        .aarch64 => aarch64.paging.freeUserAddrSpace(addr_space_root),
        else => unreachable,
    }
}

pub fn copyKernelMappings(root: VAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.copyKernelMappings(root),
        .aarch64 => aarch64.paging.copyKernelMappings(root),
        else => unreachable,
    }
}

pub fn dropIdentityMapping() void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.dropIdentityMapping(),
        .aarch64 => aarch64.paging.dropIdentityMapping(),
        else => unreachable,
    }
}

/// Classification of ELF relocation types for KASLR slide application.
pub const RelocAction = enum { skip, abs64, abs32, unsupported };

/// Classify a relocation type for KASLR processing.
pub fn classifyRelocation(rtype: u32) RelocAction {
    return switch (builtin.cpu.arch) {
        .x86_64 => {
            if (rtype == @intFromEnum(std.elf.R_X86_64.PC32) or
                rtype == @intFromEnum(std.elf.R_X86_64.PLT32) or
                rtype == @intFromEnum(std.elf.R_X86_64.NONE)) return .skip;
            if (rtype == @intFromEnum(std.elf.R_X86_64.@"64")) return .abs64;
            if (rtype == @intFromEnum(std.elf.R_X86_64.@"32S")) return .abs32;
            return .unsupported;
        },
        .aarch64 => {
            const R = std.elf.R_AARCH64;
            // PC-relative: no adjustment needed (both sides move by slide).
            // LO12: low 12 bits unchanged with page-aligned slide.
            if (rtype == @intFromEnum(R.NONE) or
                rtype == @intFromEnum(R.PREL32) or
                rtype == @intFromEnum(R.PREL64) or
                rtype == @intFromEnum(R.ADR_PREL_PG_HI21) or
                rtype == @intFromEnum(R.ADR_PREL_PG_HI21_NC) or
                rtype == @intFromEnum(R.ADR_PREL_LO21) or
                rtype == @intFromEnum(R.ADD_ABS_LO12_NC) or
                rtype == @intFromEnum(R.CALL26) or
                rtype == @intFromEnum(R.JUMP26) or
                rtype == @intFromEnum(R.LDST8_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST16_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST32_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST64_ABS_LO12_NC) or
                rtype == @intFromEnum(R.LDST128_ABS_LO12_NC)) return .skip;
            if (rtype == @intFromEnum(R.ABS64) or
                rtype == @intFromEnum(R.RELATIVE)) return .abs64;
            if (rtype == @intFromEnum(R.ABS32)) return .abs32;
            return .unsupported;
        },
        else => unreachable,
    };
}

pub fn isRelativeRelocation(rela_type: u32) bool {
    return switch (builtin.cpu.arch) {
        .x86_64 => rela_type == @intFromEnum(std.elf.R_X86_64.RELATIVE),
        .aarch64 => rela_type == @intFromEnum(std.elf.R_AARCH64.RELATIVE),
        else => unreachable,
    };
}

// ── Spec v3 paging primitives ────────────────────────────────────────
// Fine-grained per-page mapping/invalidation surface used by VAR
// install/unmap, page_frame mapcnt updates, and shootdown coordination.

/// Map a single page of size `sz` at `virt → phys` with `cch` cache
/// attributes and `perms`. Spec §[var].map_pf.
pub fn mapPageSized(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    sz: VarPageSize,
    cch: VarCacheType,
    perms: MemoryPerms,
) !void {
    switch (builtin.cpu.arch) {
        .x86_64 => try x64.paging.mapPageSized(addr_space_root, phys, virt, sz, cch, perms),
        .aarch64 => try aarch64.paging.mapPageSized(addr_space_root, phys, virt, sz, cch, perms),
        else => unreachable,
    }
}

/// Unmap a single page of size `sz` at `virt`. Returns the previously
/// mapped physical page if any. Spec §[var].unmap.
pub fn unmapPageSized(
    addr_space_root: PAddr,
    virt: VAddr,
    sz: VarPageSize,
) ?PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.unmapPageSized(addr_space_root, virt, sz),
        .aarch64 => aarch64.paging.unmapPageSized(addr_space_root, virt, sz),
        else => unreachable,
    };
}

/// Allocate a fresh empty top-level address space (PML4 root on x86-64,
/// stage-1 TTBR0 root on aarch64). Bumps the per-arch ASID/PCID
/// allocator implicitly is the caller's responsibility — this only
/// hands back the page-table root. Spec §[capability_domain].
pub fn allocAddrSpaceRoot() !PAddr {
    return switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.allocAddrSpaceRoot(),
        .aarch64 => aarch64.paging.allocAddrSpaceRoot(),
        else => unreachable,
    };
}

/// Install `root` as the active user address space on the local core,
/// tagged by `id` (PCID on x86-64, ASID on aarch64).
pub fn swapAddrSpace(root: PAddr, id: u16) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.swapAddrSpace(root, id),
        .aarch64 => aarch64.paging.swapAddrSpace(root, id),
        else => unreachable,
    }
}

/// Local-core TLB invalidation over a contiguous run of `page_count`
/// pages of size `sz` starting at `virt`. Used immediately after
/// unmapping or permission downgrades when the caller is the only core
/// that could have cached the translation.
pub fn invalidateTlbRange(
    addr_space_root: PAddr,
    virt: VAddr,
    sz: VarPageSize,
    page_count: u32,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.invalidateTlbRange(addr_space_root, virt, sz, page_count),
        .aarch64 => aarch64.paging.invalidateTlbRange(addr_space_root, virt, sz, page_count),
        else => unreachable,
    }
}

/// Cross-core TLB shootdown over the same page range, addressed by
/// `addr_space_id` so remote cores can filter quickly. Issues a
/// shootdown IPI and waits for ack from every core that may hold a
/// stale entry.
pub fn shootdownTlbRange(
    addr_space_id: u16,
    virt: VAddr,
    sz: VarPageSize,
    page_count: u32,
) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.shootdownTlbRange(addr_space_id, virt, sz, page_count),
        .aarch64 => aarch64.paging.shootdownTlbRange(addr_space_id, virt, sz, page_count),
        else => unreachable,
    }
}

/// Cross-core full-ASID/PCID shootdown. Used by `delete` of a
/// capability domain when its address space root is being torn down.
pub fn shootdownTlbAll(addr_space_id: u16) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.shootdownTlbAll(addr_space_id),
        .aarch64 => aarch64.paging.shootdownTlbAll(addr_space_id),
        else => unreachable,
    }
}

/// Invalidate cached intermediate paging structures (PML4/PDPT/PD
/// nodes on x86-64 via INVPCID type-2; TLBI ALLE1IS on aarch64).
/// Required after edits that change which leaf a higher-level walker
/// would resolve — e.g. shrinking a 2 MiB page to 4 KiB leaves.
pub fn invalidatePagingStructureCache(addr_space_root: PAddr) void {
    switch (builtin.cpu.arch) {
        .x86_64 => x64.paging.invalidatePagingStructureCache(addr_space_root),
        .aarch64 => aarch64.paging.invalidatePagingStructureCache(addr_space_root),
        else => unreachable,
    }
}

//! AArch64 page table management.
//!
//! ARM uses a 4-level page table (like x86-64) but with different terminology
//! and a split address space: TTBR0_EL1 for user (lower VA range) and
//! TTBR1_EL1 for kernel (upper VA range).
//!
//! Page table structure (4KB granule, 48-bit VA):
//!   Level 0: PGD  — bits [47:39], 512 entries, each covers 512 GB
//!   Level 1: PUD  — bits [38:30], 512 entries, each covers 1 GB
//!   Level 2: PMD  — bits [29:21], 512 entries, each covers 2 MB
//!   Level 3: PTE  — bits [20:12], 512 entries, each covers 4 KB
//!
//! Descriptor format (ARM ARM D5.3, Table D5-15):
//!   Bits [1:0]:  descriptor type
//!     0b00 = Invalid
//!     0b01 = Block (level 1/2 only — 1GB/2MB mapping)
//!     0b11 = Table (levels 0-2) or Page (level 3)
//!   Bits [47:12]: output address (physical page frame)
//!   Upper attributes [63:50]:
//!     [54] = XN (Execute Never)
//!     [53] = PXN (Privileged Execute Never)
//!     [52] = Contiguous hint
//!   Lower attributes [11:2]:
//!     [7:6] = AP (Access Permissions):
//!       0b00 = EL1 RW, EL0 no access
//!       0b01 = EL1 RW, EL0 RW
//!       0b10 = EL1 RO, EL0 no access
//!       0b11 = EL1 RO, EL0 RO
//!     [4:2] = AttrIndx (indexes into MAIR_EL1 for memory type)
//!     [10]  = AF (Access Flag — must be set or hardware generates fault)
//!     [11]  = nG (not Global — tagged with ASID if set)
//!
//! TLB maintenance (ARM ARM D5.9):
//!   After modifying a PTE: DSB ISH → TLBI VAE1IS → DSB ISH → ISB.
//!   Full ASID invalidate: TLBI ASIDE1IS.
//!   On context switch: write TTBR0_EL1 (user tables change, kernel stays in TTBR1).
//!
//! Key differences from x86 paging:
//! - Split TTBR0/TTBR1 means kernel mappings don't need to be copied into
//!   every process's page table — TTBR1 stays constant.
//!   copyKernelMappings() may be a no-op if we use TTBR1 for all kernel VAs.
//! - Explicit TLB invalidation required (no implicit invalidation on table write).
//! - AF bit must be set by software (or enable hardware AF management via TCR_EL1.HA).
//! - Memory attributes via MAIR indirection, not page table bits directly.
//!
//! Dispatch interface mapping:
//!   getAddrSpaceRoot()        → read TTBR0_EL1
//!   mapPage(root, p, v, perm) → walk/allocate table levels, set PTE, DSB+TLBI+ISB
//!   unmapPage(root, v)        → clear PTE, TLBI, return freed physical page
//!   updatePagePerms(...)      → modify AP/XN bits in PTE, TLBI
//!   resolveVaddr(root, v)     → walk tables, return PA from PTE
//!   swapAddrSpace(root)       → write TTBR0_EL1, ISB
//!   copyKernelMappings(root)  → likely no-op (TTBR1 handles kernel VA)
//!   dropIdentityMapping()     → clear level-0 entries for identity range, TLBI
//!   freeUserAddrSpace(root)   → walk and free all table pages under TTBR0
//!
//! References:
//! - ARM ARM D5.2: VMSAv8-64 translation table format
//! - ARM ARM D5.3: Translation table descriptor formats
//! - ARM ARM D5.9: TLB maintenance
//! - ARM ARM D13.2.131: TCR_EL1
//! - ARM ARM D13.2.136: TTBR0_EL1, TTBR1_EL1

const std = @import("std");
const zag = @import("zag");

const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageSize = zag.memory.paging.PageSize;
const VAddr = zag.memory.address.VAddr;

pub fn getAddrSpaceRoot() PAddr {
    @panic("aarch64 paging not implemented");
}

pub fn mapPage(
    addr_space_root: PAddr,
    phys: PAddr,
    virt: VAddr,
    perms: MemoryPerms,
) !void {
    _ = addr_space_root;
    _ = phys;
    _ = virt;
    _ = perms;
    @panic("aarch64 mapPage not implemented");
}

pub fn mapPageBoot(
    addr_space_root: VAddr,
    phys: PAddr,
    virt: VAddr,
    size: PageSize,
    perms: MemoryPerms,
    allocator: std.mem.Allocator,
) !void {
    _ = addr_space_root;
    _ = phys;
    _ = virt;
    _ = size;
    _ = perms;
    _ = allocator;
    @panic("aarch64 mapPageBoot not implemented");
}

pub fn freeUserAddrSpace(addr_space_root: PAddr) void {
    _ = addr_space_root;
    @panic("aarch64 freeUserAddrSpace not implemented");
}

pub fn unmapPage(addr_space_root: PAddr, virt: VAddr) ?PAddr {
    _ = addr_space_root;
    _ = virt;
    @panic("aarch64 unmapPage not implemented");
}

pub fn updatePagePerms(addr_space_root: PAddr, virt: VAddr, new_perms: MemoryPerms) void {
    _ = addr_space_root;
    _ = virt;
    _ = new_perms;
    @panic("aarch64 updatePagePerms not implemented");
}

pub fn resolveVaddr(addr_space_root: PAddr, virt: VAddr) ?PAddr {
    _ = addr_space_root;
    _ = virt;
    @panic("aarch64 resolveVaddr not implemented");
}

pub fn swapAddrSpace(root: PAddr) void {
    _ = root;
    @panic("aarch64 swapAddrSpace not implemented");
}

pub fn copyKernelMappings(root: VAddr) void {
    // With split TTBR0/TTBR1, kernel mappings live in TTBR1 and don't need
    // copying into per-process tables. This may be a no-op on aarch64.
    _ = root;
    @panic("aarch64 copyKernelMappings not implemented");
}

pub fn dropIdentityMapping() void {
    @panic("aarch64 dropIdentityMapping not implemented");
}

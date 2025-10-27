//! Virtual memory manager (VMM) for linear address reservations.
//!
//! Monotonic virtual-address reserver over `[start_vaddr, end_vaddr)` with
//! alignment support and a small fixed ledger of reservations. Intended for
//! handing out stable VAs for subsystems (heaps, stacks, mappings).

const std = @import("std");
const zag = @import("zag");

const paging = zag.x86.Paging;

const VAddr = paging.VAddr;

/// Errors returned by the VMM reservation API.
pub const VmmErrors = error{
    TooManyReservations,
    OutOfAddressSpace,
    InvalidSize,
};

/// Recorded reservation: base virtual address and byte size.
pub const VmmAllocation = struct {
    vaddr: VAddr,
    size: u64,
};

/// Virtual address space reserver.
///
/// Fields:
/// - `start_vaddr`: start of reservation range (inclusive).
/// - `end_vaddr`: end of reservation range (exclusive).
/// - `free_vaddr`: next free VA (monotonically increases).
/// - `vmm_allocations`: fixed-size ledger of reservations.
/// - `vmm_allocations_idx`: next write index into the ledger.
pub const VirtualMemoryManager = struct {
    start_vaddr: VAddr,
    end_vaddr: VAddr,
    free_vaddr: VAddr,

    vmm_allocations: [MAX_RESERVATIONS]VmmAllocation = undefined,
    vmm_allocations_idx: u32 = 0,

    /// Initializes a VMM over `[start_vaddr, end_vaddr)`.
    ///
    /// Arguments:
    /// - `start_vaddr`: start of the reservable VA range (inclusive).
    /// - `end_vaddr`: end of the reservable VA range (exclusive).
    ///
    /// Returns:
    /// - A `VirtualMemoryManager` with `free_vaddr = start_vaddr`.
    pub fn init(start_vaddr: VAddr, end_vaddr: VAddr) VirtualMemoryManager {
        std.debug.assert(end_vaddr.addr > start_vaddr.addr);
        return .{
            .start_vaddr = start_vaddr,
            .end_vaddr = end_vaddr,
            .free_vaddr = start_vaddr,
        };
    }

    /// Checks whether `vaddr` lies within any recorded reservation.
    ///
    /// Arguments:
    /// - `self`: VMM instance.
    /// - `vaddr`: virtual address to test.
    ///
    /// Returns:
    /// - `true` if `vaddr` is inside a reserved span; `false` otherwise.
    pub fn isValidVaddr(self: *VirtualMemoryManager, vaddr: VAddr) bool {
        var i: u32 = 0;
        while (i < self.vmm_allocations_idx) : (i += 1) {
            const base = self.vmm_allocations[i].vaddr;
            const end = VAddr.fromInt(base.addr + self.vmm_allocations[i].size);
            if (vaddr.addr >= base.addr and vaddr.addr < end.addr) return true;
        }
        return false;
    }

    /// Reserves `size` bytes at the next aligned free VA.
    ///
    /// Arguments:
    /// - `self`: VMM instance.
    /// - `size`: size in bytes to reserve (must be > 0).
    /// - `alignment`: alignment for the reservation base.
    ///
    /// Returns:
    /// - `VAddr` base of the reserved span on success.
    ///
    /// Errors:
    /// - `error.TooManyReservations`: ledger is full.
    /// - `error.InvalidSize`: size is zero.
    /// - `error.OutOfAddressSpace`: range end would exceed `end_vaddr`.
    pub fn reserve(self: *VirtualMemoryManager, size: u64, alignment: std.mem.Alignment) !VAddr {
        if (self.vmm_allocations_idx >= MAX_RESERVATIONS) return error.TooManyReservations;
        if (size == 0) return error.InvalidSize;

        const align_bytes: u64 = alignment.toByteUnits();
        const aligned = VAddr.fromInt(std.mem.alignForward(
            u64,
            self.free_vaddr.addr,
            align_bytes,
        ));
        const next = VAddr.fromInt(aligned.addr + size);
        if (next.addr > self.end_vaddr.addr) return error.OutOfAddressSpace;

        self.vmm_allocations[self.vmm_allocations_idx] = .{
            .vaddr = aligned,
            .size = size,
        };
        self.vmm_allocations_idx += 1;

        self.free_vaddr = next;
        return aligned;
    }
};

/// Maximum number of reservations tracked in the ledger.
const MAX_RESERVATIONS = 16;

/// Global VMM primarily used by the page-fault handler and early subsystems.
pub var global_vmm: ?VirtualMemoryManager = null;

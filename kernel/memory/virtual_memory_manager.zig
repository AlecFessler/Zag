//! Virtual memory manager (VMM) for linear address reservations.
//!
//! Monotonic virtual-address reserver over `[start_vaddr, end_vaddr)` with
//! alignment support and a small fixed ledger of reservations. Intended for
//! handing out stable VAs for subsystems (heaps, stacks, mappings).
//!
//! # Directory
//!
//! ## Type Definitions
//! - `VmmErrors` — error set returned by reservation operations.
//! - `VmmAllocation` — recorded reservation: base VAddr and byte size.
//! - `VirtualMemoryManager` — monotonic VA reserver with a fixed-size ledger.
//!
//! ## Constants
//! - `MAX_RESERVATIONS` — maximum number of tracked reservations.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `VirtualMemoryManager.init` — construct a VMM over a VA range.
//! - `VirtualMemoryManager.isValidVAddr` — check if an address lies in any reservation.
//! - `VirtualMemoryManager.reserve` — reserve `size` bytes at next aligned VA.

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

    /// Function: `VirtualMemoryManager.init`
    ///
    /// Summary:
    /// Initialize a VMM over `[start_vaddr, end_vaddr)`, starting with no reservations.
    ///
    /// Arguments:
    /// - `start_vaddr`: Start of the reservable VA range (inclusive).
    /// - `end_vaddr`: End of the reservable VA range (exclusive).
    ///
    /// Returns:
    /// - `VirtualMemoryManager`: Instance with `free_vaddr = start_vaddr`.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn init(start_vaddr: VAddr, end_vaddr: VAddr) VirtualMemoryManager {
        std.debug.assert(end_vaddr.addr > start_vaddr.addr);
        return .{
            .start_vaddr = start_vaddr,
            .end_vaddr = end_vaddr,
            .free_vaddr = start_vaddr,
        };
    }

    /// Function: `VirtualMemoryManager.isValidVAddr`
    ///
    /// Summary:
    /// Check whether `vaddr` lies within any recorded reservation.
    ///
    /// Arguments:
    /// - `self`: VMM instance.
    /// - `vaddr`: Virtual address to test.
    ///
    /// Returns:
    /// - `bool`: `true` if inside a reserved span; `false` otherwise.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn isValidVAddr(self: *VirtualMemoryManager, vaddr: VAddr) bool {
        var i: u32 = 0;
        while (i < self.vmm_allocations_idx) : (i += 1) {
            const base = self.vmm_allocations[i].vaddr;
            const end = VAddr.fromInt(base.addr + self.vmm_allocations[i].size);
            if (vaddr.addr >= base.addr and vaddr.addr < end.addr) return true;
        }
        return false;
    }

    /// Function: `VirtualMemoryManager.reserve`
    ///
    /// Summary:
    /// Reserve `size` bytes at the next aligned free VA and record it in the ledger.
    ///
    /// Arguments:
    /// - `self`: VMM instance.
    /// - `size`: Size in bytes to reserve (must be > 0).
    /// - `alignment`: Alignment for the reservation base.
    ///
    /// Returns:
    /// - `VAddr`: Base of the reserved span on success.
    ///
    /// Errors:
    /// - `error.TooManyReservations`: Ledger is full.
    /// - `error.InvalidSize`: `size == 0`.
    /// - `error.OutOfAddressSpace`: Reservation would exceed `end_vaddr`.
    ///
    /// Panics:
    /// - None.
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

//! Aarch64 guest memory region tracking.
//!
//! Portable port of `kernel/arch/x64/kvm/guest_memory.zig`. Nothing here
//! is arch-specific except the `vm_hw` import — the x64 and aarch64
//! copies could be unified in a future pass. For now they stay parallel
//! to match the directory layout and avoid cross-arch churn.
//!
//! Purpose: keep a small array of `(guest_phys, size, rights)` tuples
//! for every region the VMM has installed via `vm_guest_map`, so that
//! `Vm.destroy` can walk them and call `vm_hw.unmapGuestPage` per page
//! on teardown.

const zag = @import("zag");

const paging = zag.memory.paging;
const vm_hw = zag.arch.aarch64.vm;

const PAddr = zag.memory.address.PAddr;

const MAX_GUEST_REGIONS = 64;

pub const GuestRegion = struct {
    guest_phys_start: u64 = 0,
    size: u64 = 0,
    rights: u8 = 0,
    active: bool = false,
};

pub const GuestMemory = struct {
    regions: [MAX_GUEST_REGIONS]GuestRegion = .{GuestRegion{}} ** MAX_GUEST_REGIONS,
    num_regions: u32 = 0,

    /// Record a freshly-installed guest memory region. Called by
    /// `kvm.vm.guestMap` after every page in the range has been wired
    /// into stage-2.
    pub fn addRegion(self: *GuestMemory, addr: u64, size: u64, rights: u8) !void {
        if (self.num_regions >= MAX_GUEST_REGIONS) return error.MaxRegions;

        self.regions[self.num_regions] = .{
            .guest_phys_start = addr,
            .size = size,
            .rights = rights,
            .active = true,
        };
        self.num_regions += 1;
    }

    /// Tear down every tracked region, unmapping each page from the
    /// stage-2 table rooted at `arch_structures`.
    ///
    /// INVARIANT: the caller must have stopped every vCPU of the owning
    /// VM before calling this. `Vm.destroy` enforces that by driving
    /// `vcpu.destroy` for each vCPU (which sets `.exited` and IPIs the
    /// core off) before touching guest memory. Without it, a remote
    /// core could still hold a stage-2 TLB entry tagged with this VM's
    /// VMID while `unmapGuestPage` clears the descriptor out from under
    /// it. M4 #126 landed real per-IPA invalidation
    /// (`TLBI IPAS2E1IS` via `vm.invalidateStage2Ipa`), so each
    /// `unmapGuestPage` here broadcasts an IS-domain flush before
    /// returning — but the "stop every vCPU first" invariant still
    /// stands because a running guest could re-fault and re-fill
    /// the TLB between clears.
    pub fn deinit(self: *GuestMemory, arch_structures: PAddr) void {
        for (self.regions[0..self.num_regions]) |*region| {
            if (!region.active) continue;
            var offset: u64 = 0;
            while (offset < region.size) : (offset += paging.PAGE4K) {
                vm_hw.unmapGuestPage(arch_structures, region.guest_phys_start + offset);
            }
            region.active = false;
        }
        self.num_regions = 0;
    }
};

/// Stage-2 fault handler hook — currently never invoked inline, because
/// we do not demand-page guest memory (all regions are installed
/// upfront by `vm_guest_map`). Mirrors the x64 stub; kept for API
/// parity with the exit handler.
pub fn handleFault(guest_mem: *const GuestMemory, arch_structures: PAddr, guest_phys: u64) bool {
    _ = guest_mem;
    _ = arch_structures;
    _ = guest_phys;
    return false;
}

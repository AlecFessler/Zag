/// Guest physical address space management.
///
/// Tracks guest physical memory regions (created via vm_guest_map) for cleanup
/// (unmapping from EPT on destroy). EPT faults are delivered to the VMM
/// as exits — the VMM calls vm_guest_map to wire host pages into guest EPT.
const zag = @import("zag");

const vm_hw = zag.arch.x64.vm;
const paging = zag.memory.paging;

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

    /// Add a guest physical memory region.
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

    /// Tear down all guest memory mappings and free allocated pages.
    pub fn deinit(self: *GuestMemory, arch_structures: PAddr) void {
        // Unmap all guest physical pages from arch structures
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

/// Handle a guest memory fault (EPT violation). Guest memory is no longer
/// demand-paged — all mappings are established upfront via vm_guest_map. Returns
/// false so the exit is delivered to the VMM.
pub fn handleFault(guest_mem: *const GuestMemory, arch_structures: PAddr, guest_phys: u64) bool {
    _ = guest_mem;
    _ = arch_structures;
    _ = guest_phys;
    return false;
}

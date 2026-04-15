//! AArch64 stage-2 VMID allocator.
//!
//! Each VM is assigned an 8-bit VMID that is programmed into
//! `VTTBR_EL2.VMID[63:48]` on world-switch. The MMU tags every stage-2 TLB
//! entry with this VMID so that a `tlbi` for one guest cannot evict another
//! guest's translations (ARM ARM D5.10.1 "VMID-based TLB maintenance").
//!
//! Baseline ARMv8.0 gives us 8-bit VMIDs (0..=255). VMIDv2 (16-bit) exists on
//! later revisions but the rest of the Zag aarch64 port targets the baseline,
//! so we stick with 8 bits here. VMID 0 is reserved for "no guest" / host
//! context, leaving 255 allocatable VMIDs.
//!
//! ## Generation rollover
//!
//! With only 255 IDs, a busy host will eventually run out. When that happens
//! we bump a global 64-bit `generation` counter, reset the allocation cursor,
//! and flush all stage-1+2 EL1 TLB entries on the inner shareable domain
//! (ARM ARM D5.10.2 "TLB maintenance on a change of VMID assignment"). The
//! flush is mandatory: stale entries tagged with an old VMID would alias the
//! reused VMID and silently corrupt the new guest.
//!
//! Every Vm records the generation at which its `vmid` was handed out. On
//! world-switch entry (`refresh`) we compare against the live global counter;
//! if the generations differ, the VMID we cached is meaningless and we pull a
//! fresh one before programming `VTTBR_EL2`.
//!
//! ## Concurrency
//!
//! `allocate` / `refresh` / `release` can be called from any core. All state
//! mutation happens under a single `SpinLock` — contention is negligible
//! (allocation is amortized O(1) per VM lifetime) and a lock keeps the
//! rollover path race-free against concurrent allocators.
//!
//! References:
//! - ARM ARM D5.10 "VMID and TLB maintenance"
//! - ARM ARM D13.2.139 "VTTBR_EL2, Virtualization Translation Table Base"

const zag = @import("zag");

const SpinLock = zag.utils.sync.SpinLock;

/// Reserved VMID for the host / "no VM" context.
pub const HOST_VMID: u8 = 0;

/// First allocatable VMID. 0 is reserved for the host.
const FIRST_VMID: u8 = 1;

/// Last allocatable VMID (inclusive).
const LAST_VMID: u8 = 255;

/// The allocator is structurally typed: any `*T` whose `T` exposes
/// `vmid: u8` and `vmid_generation: u64` fields works. The real `Vm` lives
/// in `arch/aarch64/kvm/vm.zig`; keeping the coupling nominal rather than
/// by import avoids a circular dependency with the VM object layer.
var lock: SpinLock = .{};

/// Monotonically increasing generation counter. Starts at 1 so that a
/// freshly zeroed `Vm` (generation == 0) is always considered stale and
/// forced through `allocate` on first `refresh`.
var generation: u64 = 1;

/// Next VMID to hand out. Walks FIRST_VMID..=LAST_VMID, then rolls over.
var next: u16 = FIRST_VMID;

/// Assign a fresh (generation, vmid) pair to `vm`. Call from VM create.
pub fn allocate(vm: anytype) void {
    lock.lock();
    defer lock.unlock();
    assignLocked(vm);
}

/// Called on world-switch entry. If the VM's cached VMID belongs to an
/// older generation it is no longer valid — allocate a new one before the
/// caller programs VTTBR_EL2.
pub fn refresh(vm: anytype) void {
    lock.lock();
    defer lock.unlock();
    if (vm.vmid_generation != generation or vm.vmid == HOST_VMID) {
        assignLocked(vm);
    }
}

/// Release the VMID held by `vm`. Called on VM destroy.
///
/// We deliberately do NOT return the VMID to a free list: the allocator is
/// a simple monotonic cursor with generation-based reclamation, so per-VM
/// release is a no-op beyond clearing the VM's fields. The rollover path
/// is what actually reclaims IDs wholesale.
pub fn release(vm: anytype) void {
    vm.vmid = HOST_VMID;
    vm.vmid_generation = 0;
}

fn assignLocked(vm: anytype) void {
    if (next > LAST_VMID) {
        rolloverLocked();
    }
    vm.vmid = @intCast(next);
    vm.vmid_generation = generation;
    next += 1;
}

fn rolloverLocked() void {
    generation += 1;
    next = FIRST_VMID;
    flushStage2Tlb();
}

/// Invalidate all EL1 stage-1+2 TLB entries on the inner shareable domain.
/// Required by ARM ARM D5.10.2 whenever a VMID is reassigned to a new guest.
///
/// `dsb ishst` : order prior stores to translation tables before the tlbi.
/// `tlbi vmalls12e1is` : invalidate all stage-1+2 entries for EL1, IS.
/// `dsb ish`   : wait for the tlbi broadcast to complete.
/// `isb`       : discard any speculatively-fetched stale translations.
fn flushStage2Tlb() void {
    asm volatile (
        \\dsb ishst
        \\tlbi vmalls12e1is
        \\dsb ish
        \\isb
        ::: .{ .memory = true });
}

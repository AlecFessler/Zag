//! hyprvOS — VMM for booting Linux on Zag.
//!
//! Spec-v3 port in progress. The recv → handle → reply exit loop is
//! sketched out below; the per-exit handlers (CPUID, IO, MSR, CR, EPT)
//! and guest-RAM/asset-loading paths are the next port pass — they
//! exist in the prior-ABI form under git history (commit before this
//! one) and will be migrated atop the new `lib.syscall.recvVmExit` /
//! `replyVmExit` infrastructure.
//!
//! Lifecycle:
//!   1. Discover cap table layout (COM1 device_region, etc.).
//!   2. Allocate VmPolicy page frame; seed CPUID + CR policy tables.
//!   3. createVirtualMachine.
//!   4. Allocate guest RAM as page_frames; map_guest into the VM and
//!      map_pf into local VARs so the VMM can write bzImage + initramfs
//!      + boot_params + ACPI tables.
//!   5. createPort + create_vcpu(exit_port = port).
//!   6. recvVmExit returns the initial-state synthetic exit; populate
//!      the VmExitState with Linux boot-protocol initial state and
//!      reply.
//!   7. Loop on recvVmExit; dispatch to per-subcode handlers; reply
//!      with mods.
//!   8. On fatal exit (triple_fault / shutdown), power_shutdown.

const lib = @import("lib");

const log = @import("log.zig");

const caps = lib.caps;
const syscall = lib.syscall;

pub fn main(cap_table_base: u64) void {
    log.init(cap_table_base);
    log.print("\n=== hyprvOS (spec-v3 port stub) ===\n");
    log.print("VMM body migration in progress.\n");
    log.print("cap_table_base=0x");
    log.hex64(cap_table_base);
    log.print("\n");

    // Smoke-check that we can issue capability syscalls. info_system is
    // a no-cap-required syscall that returns core count, total phys
    // pages, and feature bits — handy as a sanity probe before we
    // start touching the per-VM machinery.
    const sys = syscall.infoSystem();
    log.print("info_system: cores=");
    log.dec(sys.v1);
    log.print(" features=0x");
    log.hex64(sys.v2);
    log.print(" total_pages=");
    log.dec(sys.v3);
    log.print(" page_size_mask=0x");
    log.hex64(sys.v4);
    log.print("\n");

    log.print("\nBoot-loop migration TODO. Halting cleanly.\n");
    _ = syscall.powerShutdown();
    while (true) asm volatile ("hlt");
}

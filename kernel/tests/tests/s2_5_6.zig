const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.5.6 — Virtual BAR read: the kernel writes the decoded port read result back into the faulting thread's register state.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const pio = t.requirePioDevice(view, "§2.5.6");
    const pio_handle = pio.handle;

    // Create a VM reservation with mmio + read + write rights.
    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.mem_reserve(0, 4096, rights.bits());
    if (vm.val < 0) {
        t.fail("§2.5.6 mem_reserve");
        syscall.shutdown();
    }
    const vm_handle: u64 = @bitCast(vm.val);
    const bar_base: u64 = vm.val2;

    // Map the PIO device into the reservation.
    const ret = syscall.mem_mmio_map(pio_handle, vm_handle, 0);
    if (ret != 0) {
        t.failWithVal("§2.5.6 mem_mmio_map", 0, ret);
        syscall.shutdown();
    }

    // Volatile read from the virtual BAR — traps to kernel, kernel decodes
    // the MOV, performs port I/O read, writes result back to register, and
    // advances RIP. If we reach the next line, emulation succeeded.
    const ptr: *volatile u8 = @ptrFromInt(bar_base);
    _ = ptr.*;

    t.pass("§2.5.6");
    syscall.shutdown();
}

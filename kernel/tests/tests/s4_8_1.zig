const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_OK: i64 = 0;

/// §4.8.1 — `mmio_map` returns `E_OK` on success.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev_entry = t.requireMmioDevice(view, "§4.8.1");
    const dev_handle = dev_entry.handle;
    const dev_size = dev_entry.deviceSizeOrPortCount();

    const page_size: u64 = 4096;
    const size = ((@as(u64, dev_size) + page_size - 1) / page_size) * page_size;
    const rights = perms.VmReservationRights{ .read = true, .write = true, .mmio = true };
    const vm = syscall.vm_reserve(0, size, rights.bits());
    const vm_handle: u64 = @bitCast(vm.val);

    const ret = syscall.mmio_map(dev_handle, vm_handle, 0);
    t.expectEqual("§4.8.1 rc", E_OK, ret);

    // Confirm the mapped BAR is accessible — a volatile read must complete
    // without faulting. AHCI MMIO at offset 0 is the CAP register, always live.
    const bar_ptr: *volatile u32 = @ptrFromInt(@as(u64, @bitCast(vm.val)));
    const cap = bar_ptr.*;
    // The value can legitimately be anything; just make sure the compiler
    // doesn't elide the load. Emit it to the sink so the read is observable.
    if (cap == 0xDEADBEEF) t.fail("§4.8.1 implausible BAR value");
    t.pass("§4.8.1 BAR accessible");
    syscall.shutdown();
}

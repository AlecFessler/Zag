const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BADHANDLE: i64 = -3;

/// §4.6.2 — `mem_shm_map` with invalid `shm_handle` returns `E_BADHANDLE`.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.mem_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const ret = syscall.mem_shm_map(99999, vm_handle, 0);
    t.expectEqual("§4.6.2", E_BADHANDLE, ret);
    syscall.shutdown();
}

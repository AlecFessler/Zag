const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §4.6.1 — `shm_map` returns `E_OK` on success.
///
/// Verifies the mapped SHM is actually accessible by writing a pattern through
/// the mapped VA and reading it back.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    const shareable_rw = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, 4096, shareable_rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    const vaddr: u64 = vm.val2;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(syscall.shm_create_with_rights(4096, shm_rights.bits()));
    const ret = syscall.shm_map(shm_handle, vm_handle, 0);
    t.expectEqual("§4.6.1", 0, ret);

    // Write a distinctive pattern and read it back.
    const buf: [*]volatile u8 = @ptrFromInt(vaddr);
    for (0..64) |i| buf[i] = @as(u8, @truncate(i)) ^ 0x5A;
    for (0..64) |i| {
        if (buf[i] != (@as(u8, @truncate(i)) ^ 0x5A)) {
            t.fail("§4.6.1 SHM read-back mismatch");
            syscall.shutdown();
        }
    }
    t.pass("§4.6.1 SHM accessible");
    syscall.shutdown();
}

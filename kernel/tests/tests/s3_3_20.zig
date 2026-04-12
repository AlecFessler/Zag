const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §3.3.20 — Capability transfer uses the last 2 payload words as handle + rights.
pub fn main(perm_view: u64) void {
    _ = perm_view;
    // Create SHM and write a magic value to it.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, 4096, vm_rights);
    if (vm.val < 0) {
        t.fail("§3.3.20");
        syscall.shutdown();
    }
    _ = syscall.mem_shm_map(shm_handle, @bitCast(vm.val), 0);
    const ptr: *volatile u64 = @ptrFromInt(vm.val2);
    ptr.* = 0xCAFE_1234;

    // Spawn child_verify_shm_transfer — it receives SHM, maps it, reads first u64, replies with value.
    const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_verify_shm_transfer.ptr),
        children.child_verify_shm_transfer.len,
        child_rights,
    )));

    // Cap transfer: last 2 words = handle + rights.
    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call_cap(ch, &.{ 0x42, shm_handle, shm_rights.bits() }, &reply);
    if (rc != 0) {
        t.failWithVal("§3.3.20", 0, rc);
        syscall.shutdown();
    }
    // Child reads SHM and replies with the value it found.
    if (reply.words[0] == 0xCAFE_1234) {
        t.pass("§3.3.20");
    } else {
        t.failWithVal("§3.3.20", @bitCast(@as(u64, 0xCAFE_1234)), @bitCast(reply.words[0]));
    }
    syscall.shutdown();
}

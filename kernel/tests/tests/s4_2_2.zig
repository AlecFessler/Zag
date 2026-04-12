/// §4.2.2 — When the VM manager process exits or is killed, the kernel destroys its VM as part of process cleanup: all vCPU threads are killed, guest memory is freed, and the VM is deallocated.
const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Spawn a child that calls vm_create then exits.
    // The kernel should clean up the VM during process teardown.
    // We observe the child becoming dead_process.
    const child_rights = perms.ProcessRights{ .spawn_thread = true };
    const rc = syscall.proc_create(
        @intFromPtr(children.child_vm_create_exit.ptr),
        children.child_vm_create_exit.len,
        child_rights.bits(),
    );
    if (rc <= 0) {
        t.fail("§4.2.2 proc_create");
        syscall.shutdown();
    }
    const child_handle: u64 = @bitCast(rc);

    // Wait for the child to exit and become dead_process.
    var attempts: u32 = 0;
    var found_dead = false;
    while (attempts < 500000) : (attempts += 1) {
        for (0..128) |i| {
            if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
                found_dead = true;
                break;
            }
        }
        if (found_dead) break;
        syscall.thread_yield();
    }

    if (found_dead) {
        t.pass("§4.2.2");
    } else {
        t.fail("§4.2.2");
    }
    syscall.shutdown();
}

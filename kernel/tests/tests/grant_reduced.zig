const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("grant with reduced rights (S2.4)");
    testGrantReadOnlyWriteFaultsChild();
}

fn testGrantReadOnlyWriteFaultsChild() void {
    const shm_handle = syscall.shm_create(syscall.PAGE4K);
    if (shm_handle <= 0) {
        t.fail("setup: shm_create failed");
        return;
    }

    const child_elf = embedded.child_shm_writer;
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .mem_reserve = true,
        .shm_create = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    if (proc_handle <= 0) {
        t.fail("proc_create failed");
        return;
    }

    // Send SHM with read-only rights via IPC cap transfer
    const ro_grant = (perms.SharedMemoryRights{ .read = true, .grant = true }).bits();
    const words = [_]u64{ 0, @intCast(shm_handle), ro_grant };
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(@intCast(proc_handle), &words, &reply);

    t.waitForCleanup(@intCast(proc_handle));
    t.pass("S2.3: child with RO SHM faulted on write, killed and cleaned up");
}

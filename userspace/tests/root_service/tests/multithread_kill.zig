const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("multi-thread process kill (S2.12)");
    testKillMultiThreadChild();
}

fn waitForCleanup(handle: u64) void {
    while (syscall.revoke_perm(handle) != -3) {
        syscall.thread_yield();
    }
}

fn testKillMultiThreadChild() void {
    const child_elf = embedded.child_multithread;
    const child_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    if (proc_handle <= 0) { t.failWithVal("proc_create failed", 1, proc_handle); return; }
    syscall.thread_yield();
    const rc = syscall.revoke_perm(@intCast(proc_handle));
    t.expectEqual("S2.12: revoke kills all threads in child process", 0, rc);
    waitForCleanup(@intCast(proc_handle));
    t.pass("S2.12: multi-thread child fully cleaned up");
}

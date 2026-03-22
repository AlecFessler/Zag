const lib = @import("lib");

const embedded = @import("embedded_children");
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("userspace stack guard pages (S2.9, S3)");
    testStackOverflowKillsChild();
}

fn waitForCleanup(handle: u64) void {
    while (syscall.revoke_perm(handle) != -3) {
        syscall.thread_yield();
    }
}

fn testStackOverflowKillsChild() void {
    const child_elf = embedded.child_stack_overflow;
    const child_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(child_elf.ptr), child_elf.len, child_rights);
    if (proc_handle <= 0) { t.failWithVal("proc_create failed", 1, proc_handle); return; }
    waitForCleanup(@intCast(proc_handle));
    t.pass("S2.9/S3: guard page fault killed child, process fully cleaned up");
}

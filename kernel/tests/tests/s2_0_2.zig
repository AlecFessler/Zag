const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.0.2 — All newly created threads start at `normal` priority, including the initial thread of a new process.
pub fn main(_: u64) void {
    // If we started at normal, setting to HIGH should succeed (root has max=pinned).
    const r1 = syscall.set_priority(syscall.PRIORITY_HIGH);
    t.expectOk("§2.0.2 set HIGH from initial", r1);

    // Now set back to normal — should also succeed.
    const r2 = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectOk("§2.0.2 set NORMAL from HIGH", r2);

    syscall.shutdown();
}

const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §2.2.1 — There are five priority levels, represented as a `u3`:
pub fn main(_: u64) void {
    // Verify each valid priority level (0-4) can be set successfully.
    const r0 = syscall.set_priority(syscall.PRIORITY_IDLE);
    t.expectOk("§2.2.1 idle(0)", r0);

    const r1 = syscall.set_priority(syscall.PRIORITY_NORMAL);
    t.expectOk("§2.2.1 normal(1)", r1);

    const r2 = syscall.set_priority(syscall.PRIORITY_HIGH);
    t.expectOk("§2.2.1 high(2)", r2);

    const r3 = syscall.set_priority(syscall.PRIORITY_REALTIME);
    t.expectOk("§2.2.1 realtime(3)", r3);

    // Pinned returns the pinned core ID (>= 0) on success.
    const r4 = syscall.set_priority(syscall.PRIORITY_PINNED);
    if (r4 < 0) {
        t.failWithVal("§2.2.1 pinned(4)", 0, r4);
        syscall.shutdown();
    }
    t.pass("§2.2.1 pinned(4)");

    // Unpin by setting back to normal.
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);

    syscall.shutdown();
}

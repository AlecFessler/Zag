const lib = @import("lib");
const std = @import("std");

const syscall = lib.syscall;
const t = lib.testing;

var thread_ran = std.atomic.Value(bool).init(false);

fn threadEntry() void {
    thread_ran.store(true, .release);
    syscall.thread_exit();
}

pub fn run() void {
    t.section("thread_create + thread_yield + set_affinity");
    testThreadCreate();
    testThreadYield();
    testSetAffinity();
    testSetAffinityBadMask();
    testThreadCreateBadAddr();
    testThreadCreateZeroPages();
}

fn testThreadCreate() void {
    thread_ran.store(false, .release);
    const rc = syscall.thread_create(&threadEntry, 0, 4);
    if (rc != 0) { t.failWithVal("thread_create failed", 0, rc); return; }
    var spins: u32 = 0;
    while (!thread_ran.load(.acquire) and spins < 500_000) : (spins += 1) {
        syscall.thread_yield();
    }
    if (thread_ran.load(.acquire)) {
        t.pass("S2.5: thread_create enqueues new thread; child ran");
    } else {
        t.fail("S2.5: spawned thread never ran");
    }
}

fn testThreadYield() void {
    syscall.thread_yield();
    t.pass("S4.thread_yield: returns E_OK");
}

fn testSetAffinity() void {
    const rc = syscall.set_affinity(1);
    t.expectEqual("S4.set_affinity: valid mask succeeds", 0, rc);
    _ = syscall.set_affinity(0xF);
}

fn testSetAffinityBadMask() void {
    const rc = syscall.set_affinity(0);
    t.expectEqual("S4.set_affinity: empty mask returns E_INVAL", -1, rc);
}

fn testThreadCreateBadAddr() void {
    const bad_entry: *const fn () void = @ptrFromInt(0xFFFF_FFFF_FFFF_0000);
    const rc = syscall.thread_create(bad_entry, 0, 4);
    t.expectEqual("S4.thread_create: entry not in user VA returns E_BADADDR", -7, rc);
}

fn testThreadCreateZeroPages() void {
    const rc = syscall.thread_create(&threadEntry, 0, 0);
    t.expectEqual("S4.thread_create: zero stack pages returns E_INVAL", -1, rc);
}

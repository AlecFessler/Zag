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
    if (rc != 0) {
        t.failWithVal("thread_create: failed", 0, rc);
        return;
    }

    var spins: u32 = 0;
    while (!thread_ran.load(.acquire) and spins < 100_000) : (spins += 1) {
        syscall.thread_yield();
    }

    if (thread_ran.load(.acquire)) {
        t.pass("thread_create: child ran");
    } else {
        t.fail("thread_create: child did not run");
    }
}

fn testThreadYield() void {
    syscall.thread_yield();
    t.pass("thread_yield: returned without fault");
}

fn testSetAffinity() void {
    const rc = syscall.set_affinity(1);
    t.expectEqual("set_affinity: core 0 only", 0, rc);

    _ = syscall.set_affinity(0xF);
}

fn testSetAffinityBadMask() void {
    const rc = syscall.set_affinity(0);
    t.expectEqual("set_affinity: zero mask rejected", -1, rc);
}

fn testThreadCreateBadAddr() void {
    const bad_entry: *const fn () void = @ptrFromInt(0xFFFF_FFFF_FFFF_0000);
    const rc = syscall.thread_create(bad_entry, 0, 4);
    t.expectEqual("thread_create: kernel addr rejected", -7, rc);
}

fn testThreadCreateZeroPages() void {
    const rc = syscall.thread_create(&threadEntry, 0, 0);
    t.expectEqual("thread_create: zero stack pages rejected", -1, rc);
}

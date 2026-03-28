const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn run() void {
    t.section("pin_exclusive syscall (S4.pin_exclusive)");
    testPinRequiresAffinity();
    testPinRequiresSingleCore();
    testPinAndRevoke();
    testDoublePin();
}

fn testPinRequiresAffinity() void {
    // Pin without setting affinity should fail (E_INVAL = -1)
    const rc = syscall.pin_exclusive();
    t.expectEqual("S4.pin_exclusive: fails without affinity set", -1, rc);
}

fn testPinRequiresSingleCore() void {
    // Set affinity to cores 1+2 (not single-core)
    _ = syscall.set_affinity(0b110);
    const rc = syscall.pin_exclusive();
    t.expectEqual("S4.pin_exclusive: fails with multi-core affinity", -1, rc);
    // Reset affinity — set to core 0 so we don't stay on a weird affinity
    _ = syscall.set_affinity(0b1);
    syscall.thread_yield();
}

fn testPinAndRevoke() void {
    // Set single-core affinity to core 3, pin, then revoke
    if (syscall.set_affinity(1 << 3) != 0) {
        t.fail("S4.pin_exclusive: set_affinity failed");
        return;
    }
    syscall.thread_yield(); // migrate to core 3

    const pin_handle = syscall.pin_exclusive();
    if (pin_handle <= 0) {
        t.fail("S4.pin_exclusive: pin failed");
        // Reset affinity
        _ = syscall.set_affinity(0b1);
        syscall.thread_yield();
        return;
    }
    t.pass("S4.pin_exclusive: pin to core 3 returned handle");

    // Revoke the pin handle to unpin
    const revoke_rc = syscall.revoke_perm(@intCast(pin_handle));
    t.expectEqual("S4.pin_exclusive: revoke unpin succeeded", 0, revoke_rc);

    // Double revoke should fail
    const revoke2 = syscall.revoke_perm(@intCast(pin_handle));
    t.expectEqual("S4.pin_exclusive: double revoke returns E_BADCAP", -3, revoke2);

    // Reset affinity
    _ = syscall.set_affinity(0b1);
    syscall.thread_yield();
}

fn testDoublePin() void {
    // Pin core 3, then try to pin core 3 again — should fail E_BUSY
    if (syscall.set_affinity(1 << 3) != 0) {
        t.fail("S4.pin_exclusive: set_affinity failed");
        return;
    }
    syscall.thread_yield();

    const h1 = syscall.pin_exclusive();
    if (h1 <= 0) {
        t.fail("S4.pin_exclusive: first pin failed");
        _ = syscall.set_affinity(0b1);
        syscall.thread_yield();
        return;
    }

    // Try pinning again on same core — should get E_BUSY (-11)
    // But actually the thread is already pinned, so it should just return an error.
    // The thread is already pinned_exclusive=true, so a second pin would try to
    // claim the same core bit which is already set.
    const h2 = syscall.pin_exclusive();
    t.expectEqual("S4.pin_exclusive: double pin same core returns E_BUSY", -11, h2);

    // Clean up
    _ = syscall.revoke_perm(@intCast(h1));
    _ = syscall.set_affinity(0b1);
    syscall.thread_yield();
}

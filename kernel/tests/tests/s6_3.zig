const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

fn waitForDeath(view: [*]const perm_view.UserViewEntry, handle: u64) perm_view.CrashReason {
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == handle) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    return view[slot].processCrashReason();
}

/// §6.3 — Fault on a private region with wrong permissions kills with `invalid_read`/`invalid_write`/`invalid_execute`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var passed = true;

    // Test 1: write to read-only private region → invalid_write
    {
        const child_rights = perms.ProcessRights{ .mem_reserve = true };
        const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_invalid_write.ptr), children.child_invalid_write.len, child_rights.bits())));
        if (waitForDeath(view, child_handle) != .invalid_write) passed = false;
    }

    // Test 2: read from write-only private region → invalid_read
    {
        const child_rights = perms.ProcessRights{ .mem_reserve = true };
        const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_invalid_read.ptr), children.child_invalid_read.len, child_rights.bits())));
        if (waitForDeath(view, child_handle) != .invalid_read) passed = false;
    }

    // Test 3: execute from non-executable private region → invalid_execute
    {
        const child_rights = perms.ProcessRights{ .mem_reserve = true };
        const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_invalid_execute.ptr), children.child_invalid_execute.len, child_rights.bits())));
        if (waitForDeath(view, child_handle) != .invalid_execute) passed = false;
    }

    if (passed) {
        t.pass("§6.3");
    } else {
        t.fail("§6.3");
    }
    syscall.shutdown();
}

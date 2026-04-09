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

/// §3.2 — Fault on SHM/MMIO region kills with `invalid_read`/`invalid_write`/`invalid_execute` based on access type.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var passed = true;

    // Test 1: write to read-only SHM → invalid_write
    {
        const shm_rights = perms.SharedMemoryRights{ .read = true, .grant = true };
        const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
        const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
        const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_shm_write_readonly.ptr), children.child_shm_write_readonly.len, child_rights)));
        var reply: syscall.IpcMessage = .{};
        _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);
        if (waitForDeath(view, child_handle) != .invalid_write) passed = false;
    }

    // Test 2: execute from non-executable private region → invalid_execute
    {
        const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
        const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_invalid_execute.ptr), children.child_invalid_execute.len, child_rights)));
        if (waitForDeath(view, child_handle) != .invalid_execute) passed = false;
    }

    if (passed) {
        t.pass("§3.2");
    } else {
        t.fail("§3.2");
    }
    syscall.shutdown();
}

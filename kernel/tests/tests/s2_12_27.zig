const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

// r14 flag bits for fault_reply
const FAULT_EXCLUDE_NEXT: u64 = 0x1;

/// Raw fault_reply syscall that passes flags in r14.
fn fault_reply_with_flags(token: u64, action: u64, modified_regs_ptr: u64, flags: u64) i64 {
    return asm volatile ("int $0x80"
        : [ret] "={rax}" (-> i64),
        : [num] "{rax}" (@intFromEnum(syscall.SyscallNum.fault_reply)),
          [a0] "{rdi}" (token),
          [a1] "{rsi}" (action),
          [a2] "{rdx}" (modified_regs_ptr),
          [flags] "{r14}" (flags),
        : .{ .rcx = true, .r11 = true, .memory = true });
}

fn findThreadEntry(view: [*]const perm_view.UserViewEntry, h: u64) ?*const perm_view.UserViewEntry {
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle == h) {
            return &view[i];
        }
    }
    return null;
}

/// §2.12.27 — `fault_reply` with `FAULT_EXCLUDE_NEXT` sets `exclude_oneshot` on the faulting thread's perm entry in the handler's table and clears `exclude_permanent`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the fault.
    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.fail("§2.12.27 fault_recv failed");
        syscall.shutdown();
    }
    const token_u: u64 = @bitCast(token);

    // Pre-seed exclude_permanent so we can prove FAULT_EXCLUDE_NEXT clears it
    // (the spec says exclude_permanent must be cleared).
    _ = syscall.fault_set_thread_mode(token_u, syscall.FAULT_MODE_EXCLUDE_PERMANENT);
    if (findThreadEntry(view, token_u)) |e| {
        if (!e.threadExcludePermanent()) {
            t.fail("§2.12.27 setup: exclude_permanent not visible");
            syscall.shutdown();
        }
    }

    // FAULT_RESUME with EXCLUDE_NEXT flag.
    const rc = fault_reply_with_flags(token_u, syscall.FAULT_RESUME, 0, FAULT_EXCLUDE_NEXT);
    if (rc != 0) {
        t.failWithVal("§2.12.27 fault_reply rc", 0, rc);
        syscall.shutdown();
    }

    // Verify exclude_oneshot is set and exclude_permanent is cleared.
    if (findThreadEntry(view, token_u)) |e| {
        if (e.threadExcludeOneshot() and !e.threadExcludePermanent()) {
            t.pass("§2.12.27");
        } else {
            t.fail("§2.12.27 wrong flag state after FAULT_EXCLUDE_NEXT");
        }
    } else {
        t.fail("§2.12.27 thread entry vanished");
    }

    // Drain the next fault (the resumed thread re-faults at the same address)
    // and kill so the test exits cleanly.
    var fault_buf2: [256]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 1);
    if (token2 >= 0) _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);
    syscall.shutdown();
}

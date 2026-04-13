const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

// r14 flag bits for fault_reply
const FAULT_EXCLUDE_PERMANENT: u64 = 0x2;

/// Raw fault_reply syscall that passes flags in r14 (x86) / x6 (aarch64).
fn fault_reply_with_flags(token: u64, action: u64, modified_regs_ptr: u64, flags: u64) i64 {
    return switch (@import("builtin").cpu.arch) {
        .x86_64 => asm volatile ("syscall"
            : [ret] "={rax}" (-> i64),
            : [num] "{rax}" (@intFromEnum(syscall.SyscallNum.fault_reply)),
              [a0] "{rdi}" (token),
              [a1] "{rsi}" (action),
              [a2] "{rdx}" (modified_regs_ptr),
              [flags] "{r14}" (flags),
            : .{ .rcx = true, .r11 = true, .memory = true }),
        .aarch64 => asm volatile ("svc #0"
            : [ret] "={x0}" (-> i64),
            : [num] "{x8}" (@intFromEnum(syscall.SyscallNum.fault_reply)),
              [a0] "{x0}" (token),
              [a1] "{x1}" (action),
              [a2] "{x2}" (modified_regs_ptr),
              [flags] "{x6}" (flags),
            : .{ .memory = true }),
        else => unreachable,
    };
}

fn findThreadEntry(view: [*]const perm_view.UserViewEntry, h: u64) ?*const perm_view.UserViewEntry {
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle == h) {
            return &view[i];
        }
    }
    return null;
}

/// §4.1.28 — `fault_reply` with `FAULT_EXCLUDE_PERMANENT` sets `exclude_permanent` on the faulting thread's perm entry in the handler's table and clears `exclude_oneshot`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    // Use the int3 child: #BP is a trap, so after FAULT_RESUME the RIP has
    // already advanced past the int3 and the thread does NOT re-fault. This
    // closes a TOCTOU window where a re-fault could fire §2.12.11 between
    // our fault_reply and our perm-view observation, clearing
    // `exclude_oneshot`/`exclude_permanent` before we see them.
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_int3_after_transfer.ptr),
        children.child_int3_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    var fault_buf: [256]u8 align(8) = undefined;
    const token = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token < 0) {
        t.fail("§4.1.28 fault_recv failed");
        syscall.shutdown();
    }
    const token_u: u64 = @bitCast(token);

    // Pre-seed exclude_oneshot so we can prove FAULT_EXCLUDE_PERMANENT clears it.
    _ = syscall.fault_set_thread_mode(token_u, syscall.FAULT_MODE_EXCLUDE_NEXT);
    if (findThreadEntry(view, token_u)) |e| {
        if (!e.threadExcludeOneshot()) {
            t.fail("§4.1.28 setup: exclude_oneshot not visible");
            syscall.shutdown();
        }
    }

    const rc = fault_reply_with_flags(token_u, syscall.FAULT_RESUME, 0, FAULT_EXCLUDE_PERMANENT);
    if (rc != 0) {
        t.failWithVal("§4.1.28 fault_reply rc", 0, rc);
        syscall.shutdown();
    }

    if (findThreadEntry(view, token_u)) |e| {
        if (e.threadExcludePermanent() and !e.threadExcludeOneshot()) {
            t.pass("§4.1.28");
        } else {
            t.fail("§4.1.28 wrong flag state after FAULT_EXCLUDE_PERMANENT");
        }
    } else {
        t.fail("§4.1.28 thread entry vanished");
    }

    syscall.shutdown();
}

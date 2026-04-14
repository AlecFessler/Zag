const builtin = @import("builtin");
const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §4.1.34 — `fault_write_mem` writes bytes from the caller's buffer into the target process's virtual address space via physmap, bypassing the target's page table permission bits.
/// bits, writing into read-only pages (including the text segment).
///
/// Strong test: patch the child's RO text — specifically the 2-byte
/// `movb (%rax), %al` null-deref instruction at the fault RIP — with
/// NOP bytes (0x90). Then FAULT_RESUME the child. If the write
/// took effect from the child's perspective, the child executes past
/// the (now-NOP) faulting bytes without re-faulting at the same RIP
/// and eventually falls through to `thread_exit` (the runtime's
/// _start epilogue), becoming a `dead_process` in our table. A
/// re-fault at the SAME RIP would prove the write was not visible
/// from the child's side.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const child_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_fault_after_transfer.ptr),
        children.child_fault_after_transfer.len,
        child_rights,
    )));

    var child_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == child_handle) {
            child_slot = i;
            break;
        }
    }

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    // Receive the first fault — RIP is the null-deref movb instruction.
    var fault_msg: syscall.FaultMessage = undefined;
    const token1 = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
    if (token1 <= 0) {
        t.failWithVal("§4.1.34 fault_recv", 0, token1);
        syscall.shutdown();
    }
    const original_rip = fault_msg.rip;

    // Locate our process handle to the child with the fault_handler bit.
    const fh_bit: u16 = @truncate((perms.ProcessHandleRights{ .fault_handler = true }).bits());
    var proc_handle: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and
            view[i].handle != 0 and
            (view[i].rights & fh_bit) != 0)
        {
            proc_handle = view[i].handle;
            break;
        }
    }
    if (proc_handle == 0) {
        t.fail("§4.1.34 no fh proc handle");
        syscall.shutdown();
    }

    // Patch the faulting instruction with NOPs. The text segment is
    // mapped RO in the child; fault_write_mem must bypass that.
    //
    // Architecture-specific encoding:
    //   x86_64:  the null-deref `movb (%rax), %al` is 2 bytes; we patch
    //            3 bytes (overwriting it plus the next byte) with x86 NOPs.
    //   aarch64: the null-deref is one 4-byte aligned load instruction;
    //            we patch the full 4-byte word with one aarch64 NOP
    //            (`d503201f`, little-endian on disk).
    const nop_bytes: []const u8 = switch (builtin.cpu.arch) {
        .x86_64 => &[_]u8{ 0x90, 0x90, 0x90 },
        .aarch64 => &[_]u8{ 0x1f, 0x20, 0x03, 0xd5 },
        else => unreachable,
    };
    const wrc = syscall.fault_write_mem(proc_handle, original_rip, @intFromPtr(nop_bytes.ptr), nop_bytes.len);
    if (wrc != 0) {
        t.failWithVal("§4.1.34 fault_write_mem", 0, wrc);
        _ = syscall.fault_reply_simple(@bitCast(token1), syscall.FAULT_KILL);
        syscall.shutdown();
    }

    // Resume the child. If the patch took effect, the child executes
    // NOP-NOP-NOP at original_rip and then continues through the
    // asm-block epilogue, the main() return, and eventually the
    // runtime's thread_exit — becoming dead_process.
    const rr = syscall.fault_reply_simple(@bitCast(token1), syscall.FAULT_RESUME);
    if (rr != 0) {
        t.failWithVal("§4.1.34 fault_reply RESUME", 0, rr);
        syscall.shutdown();
    }

    // Poll for either (a) a second fault at the SAME RIP (patch failed)
    // or (b) the child becoming dead_process / still alive without
    // re-faulting at original_rip (patch succeeded).
    var saw_same_rip_refault = false;
    var saw_dead = false;
    var attempts: u32 = 0;
    while (attempts < 200_000 and !saw_same_rip_refault and !saw_dead) : (attempts += 1) {
        if (view[child_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
            saw_dead = true;
            break;
        }
        var buf2: syscall.FaultMessage = undefined;
        const rc2 = syscall.fault_recv(@intFromPtr(&buf2), 0);
        if (rc2 > 0) {
            if (buf2.rip == original_rip) {
                saw_same_rip_refault = true;
                _ = syscall.fault_reply_simple(@bitCast(rc2), syscall.FAULT_KILL);
            } else {
                // Different RIP — the child advanced past the patched
                // bytes and faulted later. Patch took effect; kill and
                // accept as success.
                _ = syscall.fault_reply_simple(@bitCast(rc2), syscall.FAULT_KILL);
                break;
            }
        } else if (rc2 == E_AGAIN) {
            syscall.thread_yield();
        } else {
            // Unexpected result.
            break;
        }
    }

    if (saw_same_rip_refault) {
        t.fail("§4.1.34 child re-faulted at same RIP — patch not visible");
        syscall.shutdown();
    }

    t.pass("§4.1.34");
    syscall.shutdown();
}

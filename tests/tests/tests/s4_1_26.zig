const builtin = @import("builtin");
const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

// Architecture-dependent FaultMessage / SavedRegs sizes.
//   x86_64:  fault_gpr_count=15 → fault_regs_size=144, fault_msg_size=176
//   aarch64: fault_gpr_count=31 → fault_regs_size=272, fault_msg_size=304
const fault_gpr_count: usize = switch (builtin.cpu.arch) {
    .x86_64 => 15,
    .aarch64 => 31,
    else => unreachable,
};
const fault_regs_size: usize = (3 + fault_gpr_count) * @sizeOf(u64);
const fault_msg_size: usize = 32 + fault_regs_size;

// Length of the first null-deref instruction emitted by the child:
// x86 `mov al, [rax]` is 2 bytes; aarch64 `ldrb w*, [x*]` is 4 bytes.
const first_insn_len: u64 = switch (builtin.cpu.arch) {
    .x86_64 => 2,
    .aarch64 => 4,
    else => unreachable,
};

/// §4.1.26 — `fault_reply` with `FAULT_RESUME_MODIFIED` resumes the faulting thread with its register state replaced by the contents of `modified_regs_ptr` (must be a readable region of `sizeof(arch.SavedRegs)` bytes).
///
/// Setup: spawn child_double_fault_after_transfer — after transferring
/// fault_handler to us, it executes two consecutive 2-byte null-deref
/// instructions. The first faults at virtual address 0x0, the second (if
/// reached) at 0xCAFE0000. Strategy: after the first fault we advance the
/// saved RIP by 2 bytes via FAULT_RESUME_MODIFIED. Correct kernel behavior
/// is to resume the thread at the second instruction, producing a second
/// fault at a distinct address we can observe.
pub fn main(_: u64) void {
    const child_rights = (perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
    }).bits();
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_double_fault_after_transfer.ptr),
        children.child_double_fault_after_transfer.len,
        child_rights,
    )));

    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(child_handle, &.{}, &reply);

    var fault_buf: [fault_msg_size]u8 align(8) = undefined;
    const token1 = syscall.fault_recv(@intFromPtr(&fault_buf), 1);
    if (token1 < 0) {
        t.failWithVal("§4.1.26 fault_recv 1", 0, token1);
        syscall.shutdown();
    }
    // Read header fields directly to avoid the x86-sized libz FaultMessage.
    const first_addr: u64 = @as(*align(8) const u64, @ptrCast(&fault_buf[24])).*;
    const first_ip: u64 = @as(*align(8) const u64, @ptrCast(&fault_buf[32])).*;

    // Build a SavedRegs blob from the FaultMessage tail (offset 32) and bump
    // the saved IP past the first null-deref instruction.
    var modified_regs: [fault_regs_size]u8 align(8) = undefined;
    @memcpy(modified_regs[0..fault_regs_size], fault_buf[32 .. 32 + fault_regs_size]);
    const ip_slot: *align(8) u64 = @ptrCast(&modified_regs[0]);
    ip_slot.* = first_ip + first_insn_len;

    const rc = syscall.fault_reply_action(
        @bitCast(token1),
        syscall.FAULT_RESUME_MODIFIED,
        @intFromPtr(&modified_regs),
    );
    if (rc != 0) {
        t.failWithVal("§4.1.26 fault_reply", 0, rc);
        syscall.shutdown();
    }

    // Expect a second fault at 0xCAFE0000 (distinct from the first at 0x0).
    var fault_buf2: [fault_msg_size]u8 align(8) = undefined;
    const token2 = syscall.fault_recv(@intFromPtr(&fault_buf2), 1);
    if (token2 < 0) {
        t.failWithVal("§4.1.26 fault_recv 2", 0, token2);
        syscall.shutdown();
    }
    const second_addr: u64 = @as(*align(8) const u64, @ptrCast(&fault_buf2[24])).*;
    if (second_addr != first_addr and second_addr == 0xCAFE0000) {
        t.pass("§4.1.26");
    } else {
        t.failWithVal("§4.1.26 second fault addr", 0xCAFE0000, @bitCast(second_addr));
    }

    _ = syscall.fault_reply_simple(@bitCast(token2), syscall.FAULT_KILL);
    syscall.shutdown();
}

//! Debugger child for the prof test OS debugger scenario.
//!
//! Receives the debuggee's slide-anchor and breakpoint addresses, then
//! becomes the debuggee's external fault handler and drives a source-
//! level step loop over the bp_stop_N symbols forever. Rotates the
//! "disarmed" breakpoint as the debuggee advances so exactly one of the
//! three bps is patched back to its original byte at any time.
//!
//! Arch note: on x86_64 we poke a 1-byte int3 (0xCC). On aarch64 we
//! poke a 4-byte `brk #0` (0xD4200000 little-endian). The kernel
//! delivers #BP / BRK as `fault_reason = breakpoint` (14) per §4.1.12.
//!
//! Rewind semantics:
//!   * x86_64 int3 is a trap — the reported fault_addr / rip points at
//!     the instruction *after* the 0xCC byte. We rewind rip by 1 so the
//!     restored instruction re-executes naturally. Done by copying the
//!     kernel-written regs blob into a fresh local buffer, rewriting
//!     byte offset 0 (ip), and passing that buffer to
//!     fault_reply_action(FAULT_RESUME_MODIFIED).
//!   * aarch64 BRK is a sync exception reported at the BRK instruction
//!     itself (ELR_EL1 = BRK address). We just resume with the original
//!     4 bytes restored.

const builtin = @import("builtin");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const prof_lib = @import("prof_lib");
const protocol = prof_lib.protocol;

const BP_COUNT: usize = 3;
const INT3: u8 = 0xCC;
const BRK_BYTES: [4]u8 = .{ 0x00, 0x00, 0x20, 0xD4 };

const BpInsnLen: usize = switch (builtin.cpu.arch) {
    .x86_64 => 1,
    .aarch64 => 4,
    else => unreachable,
};

const Breakpoint = struct {
    runtime_addr: u64,
    saved: [4]u8,
    armed: bool,
};

var bps: [BP_COUNT]Breakpoint = undefined;

/// Index of the currently-disarmed bp, or BP_COUNT when all are armed.
var disarmed_idx: usize = BP_COUNT;

fn writeMem(debuggee_h: u64, vaddr: u64, bytes: []const u8) bool {
    return syscall.fault_write_mem(debuggee_h, vaddr, @intFromPtr(bytes.ptr), bytes.len) == 0;
}

fn readMem(debuggee_h: u64, vaddr: u64, out: []u8) bool {
    return syscall.fault_read_mem(debuggee_h, vaddr, @intFromPtr(out.ptr), out.len) == 0;
}

fn armBp(debuggee_h: u64, idx: usize) void {
    const bp = &bps[idx];
    if (bp.armed) return;
    switch (builtin.cpu.arch) {
        .x86_64 => {
            const one = [1]u8{INT3};
            _ = writeMem(debuggee_h, bp.runtime_addr, one[0..]);
        },
        .aarch64 => {
            _ = writeMem(debuggee_h, bp.runtime_addr, BRK_BYTES[0..]);
        },
        else => unreachable,
    }
    bp.armed = true;
}

fn disarmBp(debuggee_h: u64, idx: usize) void {
    const bp = &bps[idx];
    if (!bp.armed) return;
    _ = writeMem(debuggee_h, bp.runtime_addr, bp.saved[0..BpInsnLen]);
    bp.armed = false;
}

fn installBps(debuggee_h: u64) bool {
    for (&bps) |*bp| {
        if (!readMem(debuggee_h, bp.runtime_addr, bp.saved[0..BpInsnLen])) return false;
        bp.armed = false;
    }
    for (0..BP_COUNT) |i| armBp(debuggee_h, i);
    return true;
}

fn findHitIndex(fault_addr: u64) ?usize {
    // x86_64 int3 is a trap: reported rip is the byte *after* the 0xCC,
    // so the originating bp lives at fault_addr - 1.
    // aarch64 BRK is reported at the BRK itself.
    const probe: u64 = switch (builtin.cpu.arch) {
        .x86_64 => fault_addr -% 1,
        .aarch64 => fault_addr,
        else => unreachable,
    };
    for (&bps, 0..) |bp, i| {
        if (bp.runtime_addr == probe) return i;
    }
    return null;
}

fn findDebuggeeHandle(pv: u64) u64 {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var i: usize = 1;
    while (i < 128) : (i += 1) {
        if (view[i].entry_type != perm_view.ENTRY_TYPE_PROCESS) continue;
        if (view[i].handle == 0) continue;
        const phr: perms.ProcessHandleRights = @bitCast(@as(u16, @truncate(view[i].rights)));
        if (phr.fault_handler) return view[i].handle;
    }
    return 0;
}

pub fn main(pv: u64) void {
    // Phase 1: first IPC from debuggee is the hello message carrying
    // runtime addresses. Verb header in word 0; slide anchor in word 1;
    // bp addresses in words 2..4.
    var m: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &m) != 0) {
        while (true) syscall.thread_yield();
    }
    const verb = protocol.headerVerb(m.words[0]);
    if (verb != @intFromEnum(protocol.DbgVerb.hello)) {
        while (true) syscall.thread_yield();
    }
    bps[0] = .{ .runtime_addr = m.words[2], .saved = undefined, .armed = false };
    bps[1] = .{ .runtime_addr = m.words[3], .saved = undefined, .armed = false };
    bps[2] = .{ .runtime_addr = m.words[4], .saved = undefined, .armed = false };
    _ = syscall.ipc_reply(&.{});

    // Phase 2: second IPC is the fault_handler cap-transfer call. After
    // ipc_recv returns, our perm table has a new PROCESS entry for the
    // debuggee carrying the fault_handler bit.
    if (syscall.ipc_recv(true, &m) != 0) {
        while (true) syscall.thread_yield();
    }
    const debuggee_h = findDebuggeeHandle(pv);
    if (debuggee_h == 0) {
        while (true) syscall.thread_yield();
    }

    // Install all breakpoints BEFORE releasing the debuggee so the first
    // bp_stop call the debuggee makes traps into us.
    if (!installBps(debuggee_h)) {
        _ = syscall.ipc_reply(&.{});
        while (true) syscall.thread_yield();
    }
    _ = syscall.ipc_reply(&.{});

    // Phase 3: fault handling loop.
    var fault_msg: syscall.FaultMessage = undefined;
    var regs_buf: [144]u8 align(8) = undefined;
    while (true) {
        const token_i = syscall.fault_recv(@intFromPtr(&fault_msg), 1);
        if (token_i <= 0) continue;
        const token: u64 = @bitCast(token_i);

        const hit = findHitIndex(fault_msg.fault_addr) orelse {
            _ = syscall.fault_reply_simple(token, syscall.FAULT_KILL);
            continue;
        };

        // Disarm the newly hit bp and rearm the previously disarmed one
        // so only the one we're standing on is patched at any time.
        if (disarmed_idx != BP_COUNT and disarmed_idx != hit) {
            armBp(debuggee_h, disarmed_idx);
        }
        disarmBp(debuggee_h, hit);
        disarmed_idx = hit;

        switch (builtin.cpu.arch) {
            .x86_64 => {
                // Copy the kernel-written regs blob into a fresh aligned
                // local buffer, rewrite ip at offset 0 to point back at
                // the bp, and pass the buffer as modified_regs_ptr.
                const src: [*]const u8 = @ptrCast(&fault_msg.rip);
                @memcpy(regs_buf[0..144], src[0..144]);
                @as(*align(8) u64, @ptrCast(&regs_buf[0])).* = bps[hit].runtime_addr;
                _ = syscall.fault_reply_action(
                    token,
                    syscall.FAULT_RESUME_MODIFIED,
                    @intFromPtr(&regs_buf),
                );
            },
            .aarch64 => {
                _ = syscall.fault_reply_simple(token, syscall.FAULT_RESUME);
            },
            else => unreachable,
        }
    }
}

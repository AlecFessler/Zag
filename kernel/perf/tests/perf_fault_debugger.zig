const children = @import("embedded_children");
const lib = @import("lib");

const bench = lib.bench;
const perms = lib.perms;
const syscall = lib.syscall;

/// Full debugger round-trip benchmark. Exercises the cross-address-space
/// memory poke + breakpoint trap + restore pattern used by gdb, strace,
/// ptrace-style tracers, and any tool that instruments another process
/// by patching its code:
///
///   parent: fault_write_mem(child, bp_addr, 0xCC)  // insert int3
///   child:  runs its code, hits bp_addr, traps
///   parent: fault_recv → {token, rip, ...}
///   parent: fault_write_mem(child, bp_addr, original_byte)  // restore
///   parent: fault_reply_action(FAULT_RESUME_MODIFIED, rip = bp_addr)
///   child:  executes restored byte, loops back
///
/// Measures the complete cycle: two fault_write_mem calls (one per side
/// of the breakpoint), fault_recv, fault_reply_action. This is the hot
/// path for a breakpoint-based tracer and a useful upper bound on the
/// "remote observe + mutate" primitive cost.
///
/// Register snapshot handling: `fault_reply_action` with
/// `FAULT_RESUME_MODIFIED` applies 144 bytes of register state verbatim
/// (rip + rflags + rsp + 15 GPRs, see kernel/arch/x64/interrupts.zig:
/// applyFaultRegs). We must NOT zero-fill that buffer — doing so clears
/// IF, nukes rsp, and zeros GPRs mid-function. Instead we re-use the
/// saved-regs block from the received FaultMessage (offset 32, 144 bytes)
/// and only overwrite rip.
const FAULT_REGS_OFFSET: usize = 32;
const FAULT_REGS_SIZE: usize = 144;

pub fn main(_: u64) void {
    _ = syscall.set_priority(syscall.PRIORITY_NORMAL);
    _ = syscall.set_affinity(1);
    _ = syscall.set_priority(syscall.PRIORITY_REALTIME);

    // `fault_handler` is the process-level right the child needs so it
    // can cap-transfer HANDLE_SELF+fault_handler back to us. The kernel
    // upgrades our existing handle to the child with fault_handler bit
    // during the cap transfer, which is what fault_read_mem/write_mem
    // check (kernel/syscall/fault.zig:383, 426).
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .fault_handler = true,
        .set_affinity = true,
    };
    const ch_rc = syscall.proc_create(
        @intFromPtr(children.child_perf_debug_target.ptr),
        children.child_perf_debug_target.len,
        child_rights.bits(),
    );
    if (ch_rc < 0) {
        syscall.write("[PERF] fault_debugger SKIP proc_create failed\n");
        syscall.shutdown();
    }
    const ch: u64 = @bitCast(ch_rc);

    // Round 1: child reports hot loop address.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(ch, &.{}, &reply);
    const bp_addr: u64 = reply.words[0];

    // Round 2: child cap-transfers fault_handler to us.
    _ = syscall.ipc_call(ch, &.{}, &reply);

    // Read the original byte (0xC3 = ret, guaranteed by naked hotLoop).
    var orig: [1]u8 = undefined;
    const read_rc = syscall.fault_read_mem(ch, bp_addr, @intFromPtr(&orig), 1);
    if (read_rc != 0) {
        syscall.write("[PERF] fault_debugger SKIP fault_read_mem failed\n");
        _ = syscall.revoke_perm(ch);
        syscall.shutdown();
    }

    const ITERATIONS: u32 = 1000;
    const buf_ptr = bench.allocBuf(ITERATIONS) orelse {
        syscall.write("[PERF] fault_debugger SKIP alloc failed\n");
        _ = syscall.revoke_perm(ch);
        syscall.shutdown();
    };
    const buf = buf_ptr[0..ITERATIONS];

    var int3: [1]u8 = .{0xCC};
    var fault_buf: [256]u8 align(8) = undefined;

    // Warmup: run a few cycles to get both processes in cache.
    var w: u32 = 0;
    while (w < 50) : (w += 1) {
        _ = runOneCycle(ch, bp_addr, &int3, &orig, &fault_buf);
    }

    var i: u32 = 0;
    while (i < ITERATIONS) : (i += 1) {
        const t0 = bench.rdtscp();
        if (!runOneCycle(ch, bp_addr, &int3, &orig, &fault_buf)) break;
        const t1 = bench.rdtscp();
        buf[i] = t1 -% t0;
    }

    if (i > 0) {
        bench.report("fault_debugger_cycle", bench.computeStats(buf[0..i], @intCast(i)));
    }

    _ = syscall.revoke_perm(ch);
    syscall.shutdown();
}

/// One debugger round trip: insert int3 → wait for trap → restore → resume.
fn runOneCycle(
    ch: u64,
    bp_addr: u64,
    int3: *const [1]u8,
    orig: *const [1]u8,
    fault_buf: *[256]u8,
) bool {
    // Insert breakpoint.
    if (syscall.fault_write_mem(ch, bp_addr, @intFromPtr(int3), 1) != 0) return false;

    // Wait for the child to hit it.
    const token = syscall.fault_recv(@intFromPtr(fault_buf), 1);
    if (token < 0) return false;

    // Restore original byte so the child can make forward progress.
    if (syscall.fault_write_mem(ch, bp_addr, @intFromPtr(orig), 1) != 0) return false;

    // Rewind rip to the breakpoint address so the restored byte executes.
    // int3 is a single-byte trap; rip on the fault message points one byte
    // past it, so bp_addr == fm.rip - 1 is the faulted instruction.
    //
    // The modified-regs buffer is the saved-regs block *from the fault*,
    // with only rip overwritten. Zero-filling would clear rflags (drops
    // IF), rsp, and every GPR — the child would crash on the first cycle.
    const regs_ptr: [*]u8 = @as([*]u8, @ptrCast(fault_buf)) + FAULT_REGS_OFFSET;
    const rip_slot: *u64 = @ptrCast(@alignCast(regs_ptr));
    rip_slot.* = bp_addr;
    _ = syscall.fault_reply_action(
        @bitCast(token),
        syscall.FAULT_RESUME_MODIFIED,
        @intFromPtr(regs_ptr),
    );
    return true;
}

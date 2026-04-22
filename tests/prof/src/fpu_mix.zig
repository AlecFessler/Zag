//! kprof workload — exercises the FPU lazy-save path with three threads
//! pinned to one core, plus a peer process for IPC round trips.
//!
//! Threads in the root process (all pinned to core 0):
//!   - fpuThread: dirties XMM/V regs every iteration before yielding,
//!     so it must displace the FPU on the local core.
//!   - intThread: pure GP-register work + yield. Should never trigger
//!     an FPU trap once lazy FPU is in place.
//!   - ipcThread: ipc_call round trips against child_ipc_echo. Tests
//!     the syscall fast path under cross-process traffic; the call/recv
//!     pair never touches FPU state, so under lazy FPU it should pay
//!     zero save/restore cost.
//!
//! After all three threads complete ITERATIONS rounds, the last one
//! to finish triggers shutdown so the kprof dump flushes.

const children = @import("embedded_children");
const lib = @import("lib");
const builtin = @import("builtin");

const perms = lib.perms;
const syscall = lib.syscall;

const ITERATIONS: u64 = 30;
const PIN_CORE_MASK: u64 = 1; // core 0 only
const STACK_PAGES: u64 = 4;

var done_count: u64 = 0;
var ipc_target: u64 = 0;

/// Touch FP/SIMD registers so the lazy-FPU machinery has to swap on us.
/// The asm is intentionally tiny — we want to measure trap/swap cost,
/// not raw FP throughput.
inline fn doFpuWork() void {
    if (builtin.cpu.arch == .x86_64) {
        asm volatile (
            \\xorps %%xmm0, %%xmm0
            \\xorps %%xmm1, %%xmm1
            \\addps %%xmm1, %%xmm0
            \\addps %%xmm0, %%xmm1
            \\addps %%xmm1, %%xmm0
            \\addps %%xmm0, %%xmm1
            ::: .{ .xmm0 = true, .xmm1 = true });
    } else if (builtin.cpu.arch == .aarch64) {
        asm volatile (
            \\fadd v0.4s, v0.4s, v0.4s
            \\fadd v1.4s, v0.4s, v0.4s
            \\fadd v0.4s, v1.4s, v0.4s
            \\fadd v1.4s, v0.4s, v1.4s
            ::: .{ .v0 = true, .v1 = true });
    }
}

/// Equivalent integer work — same number of register-to-register ops,
/// no FPU touch. Marks the regs as clobbered so LLVM doesn't fold.
inline fn doIntegerWork() void {
    if (builtin.cpu.arch == .x86_64) {
        asm volatile (
            \\xorq %%rax, %%rax
            \\xorq %%rbx, %%rbx
            \\addq %%rbx, %%rax
            \\addq %%rax, %%rbx
            \\addq %%rbx, %%rax
            \\addq %%rax, %%rbx
            ::: .{ .rax = true, .rbx = true });
    } else if (builtin.cpu.arch == .aarch64) {
        asm volatile (
            \\add x9, x9, x9
            \\add x10, x9, x9
            \\add x9, x10, x9
            \\add x10, x9, x10
            ::: .{ .x9 = true, .x10 = true });
    }
}

fn fpuThread() void {
    _ = syscall.set_affinity(PIN_CORE_MASK);
    var i: u64 = 0;
    while (i < ITERATIONS) {
        doFpuWork();
        _ = syscall.thread_yield();
        i += 1;
    }
    _ = @atomicRmw(u64, &done_count, .Add, 1, .release);
    syscall.thread_exit();
}

fn intThread() void {
    _ = syscall.set_affinity(PIN_CORE_MASK);
    var i: u64 = 0;
    while (i < ITERATIONS) {
        doIntegerWork();
        _ = syscall.thread_yield();
        i += 1;
    }
    _ = @atomicRmw(u64, &done_count, .Add, 1, .release);
    syscall.thread_exit();
}

fn ipcThread() void {
    _ = syscall.set_affinity(PIN_CORE_MASK);
    var counter: u64 = 0;
    var i: u64 = 0;
    while (i < ITERATIONS) {
        var reply: syscall.IpcMessage = .{};
        const rc = syscall.ipc_call(ipc_target, &.{counter}, &reply);
        if (rc != 0) {
            _ = syscall.thread_yield();
            continue;
        }
        counter = reply.words[0];
        i += 1;
    }
    _ = @atomicRmw(u64, &done_count, .Add, 1, .release);
    syscall.thread_exit();
}

pub fn main(_: u64) void {
    _ = syscall.set_affinity(PIN_CORE_MASK);

    // Spawn the IPC echo peer as a separate process so the IPC round
    // trips are real cross-process traffic, not intra-process queuing.
    const child_rights = (perms.ProcessRights{}).bits();
    const ch_rc: i64 = syscall.proc_create(
        @intFromPtr(children.child_ipc_echo.ptr),
        children.child_ipc_echo.len,
        child_rights,
    );
    if (ch_rc < 0) {
        while (true) _ = syscall.thread_yield();
    }
    ipc_target = @bitCast(ch_rc);

    _ = syscall.thread_create(&fpuThread, 0, STACK_PAGES);
    _ = syscall.thread_create(&intThread, 0, STACK_PAGES);
    _ = syscall.thread_create(&ipcThread, 0, STACK_PAGES);

    while (@atomicLoad(u64, &done_count, .acquire) < 3) {
        _ = syscall.thread_yield();
    }

    syscall.shutdown();
}

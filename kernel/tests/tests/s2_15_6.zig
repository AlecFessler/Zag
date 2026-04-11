const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var spinner_ready: u64 align(8) = 0;
var spinner_stop: u64 align(8) = 0;

fn spinner() void {
    // Pin to core 0 so we know which CoreInfo entry to look at.
    if (syscall.set_affinity(0b1) != syscall.E_OK) {
        @atomicStore(u64, &spinner_ready, 0xffff_ffff_ffff_ffff, .seq_cst);
        return;
    }
    @atomicStore(u64, &spinner_ready, 1, .seq_cst);
    var acc: u64 = 0;
    while (@atomicLoad(u64, &spinner_stop, .seq_cst) == 0) {
        acc +%= 1;
        // No yield — we want the scheduler to see this core as busy when
        // the parent polls sys_info. A yield every iteration would let
        // the idle thread slip in between ticks and confuse the check.
    }
    // Prevent optimisation.
    @atomicStore(u64, &spinner_stop, acc | 0x8000_0000_0000_0000, .seq_cst);
}

/// §2.15.6 — A value of `0` means the core is active; higher values indicate progressively deeper idle states.
///
/// Pin a busy-spinning thread to core 0 and poll `sys_info` until core 0's
/// `c_state` reads as 0 (active). A correct kernel sets `c_state = 0` when
/// the running thread on that core is not the idle thread. We allow a
/// reasonable number of poll iterations because the spinner may not have
/// been dispatched yet on the first read, and the sys_info call itself can
/// land on a tick boundary where the idle thread had briefly been
/// re-selected. Any non-zero value for `c_state` while the spinner is
/// known-busy would mean the kernel is reporting a deeper idle state for
/// an active core, which violates the tag.
pub fn main(_: u64) void {
    // Pin parent off core 0 so the spinner has the core to itself on
    // multi-core rigs. On single-core QEMU this is a no-op.
    _ = syscall.set_affinity(~@as(u64, 0b1));

    const rc = syscall.thread_create(&spinner, 0, 4);
    if (rc <= 0) {
        t.fail("§2.15.6 thread_create");
        syscall.shutdown();
    }
    const handle: u64 = @bitCast(rc);

    while (@atomicLoad(u64, &spinner_ready, .seq_cst) == 0) syscall.thread_yield();
    if (@atomicLoad(u64, &spinner_ready, .seq_cst) == 0xffff_ffff_ffff_ffff) {
        t.fail("§2.15.6 spinner set_affinity");
        @atomicStore(u64, &spinner_stop, 1, .seq_cst);
        _ = syscall.thread_kill(handle);
        syscall.shutdown();
    }

    var info: syscall.SysInfo = undefined;
    var cores: [syscall.MAX_CPU_CORES]syscall.CoreInfo = undefined;
    var saw_active: bool = false;

    var tries: u32 = 0;
    while (tries < 32) : (tries += 1) {
        // Let the spinner run for a few ticks between samples.
        var k: u64 = 0;
        while (k < 8) : (k += 1) syscall.thread_yield();

        if (syscall.sys_info(@intFromPtr(&info), @intFromPtr(&cores)) != syscall.E_OK) {
            t.fail("§2.15.6 sys_info");
            @atomicStore(u64, &spinner_stop, 1, .seq_cst);
            _ = syscall.thread_kill(handle);
            syscall.shutdown();
        }
        if (info.core_count == 0) continue;
        // Core 0 is always valid (core_count >= 1). Check its c_state.
        if (cores[0].c_state == 0) {
            saw_active = true;
            break;
        }
    }

    @atomicStore(u64, &spinner_stop, 1, .seq_cst);
    _ = syscall.thread_kill(handle);

    if (!saw_active) {
        t.failWithVal(
            "§2.15.6 core 0 never reported c_state=0 while busy",
            0,
            @intCast(cores[0].c_state),
        );
        syscall.shutdown();
    }

    t.pass("§2.15.6");
    syscall.shutdown();
}

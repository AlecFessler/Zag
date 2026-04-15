//! Debuggee child for the prof test OS debugger scenario.
//!
//! Bootstrap:
//!   1. ipc_recv: wait for root to cap-transfer the debugger handle.
//!   2. Scan perm_view for the new PROCESS entry -> debugger_h.
//!   3. ipc_call(debugger_h, DbgVerb.hello, slide anchor + bp_stop_* addrs)
//!      so the debugger can place source-level breakpoints.
//!   4. ipc_call_cap(debugger_h, {HANDLE_SELF, fault_handler bits}) so the
//!      debugger becomes our external fault handler (§2.12.3 / §4.1).
//!   5. Enter a loop that steps through bp_stop_1 .. bp_stop_4 forever.
//!      Each stop is a distinct `noinline` function whose symbol address
//!      becomes a stable breakpoint slot for the debugger.

const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const prof_lib = @import("prof_lib");
const protocol = prof_lib.protocol;

/// Slide anchor: debugger parses debuggee ELF symbol table, finds this
/// function's static address, then computes slide = runtime - static.
pub export fn debuggee_slide_anchor() callconv(.c) void {
    asm volatile ("" ::: .{ .memory = true });
}

/// Breakpoint slots. Kept `export` so each gets a unique ELF symbol the
/// debugger can look up by name. Body is a memory-barrier so LLVM can't
/// dead-store eliminate it when the caller ignores the return.
pub export fn bp_stop_1() callconv(.c) void {
    asm volatile ("" ::: .{ .memory = true });
}

pub export fn bp_stop_2() callconv(.c) void {
    asm volatile ("" ::: .{ .memory = true });
}

pub export fn bp_stop_3() callconv(.c) void {
    asm volatile ("" ::: .{ .memory = true });
}

pub export fn bp_stop_4() callconv(.c) void {
    asm volatile ("" ::: .{ .memory = true });
}

fn findDebuggerHandle(pv: u64) u64 {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var i: usize = 1;
    while (i < 128) : (i += 1) {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_PROCESS and view[i].handle != 0) {
            return view[i].handle;
        }
    }
    return 0;
}

pub fn main(pv: u64) void {
    // Phase 1: receive the cap transfer from root that places a debugger
    // handle into our perm table. Root sends (debugger_h, send_words).
    var m: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &m) != 0) {
        while (true) syscall.thread_yield();
    }
    _ = syscall.ipc_reply(&.{});

    const debugger_h = findDebuggerHandle(pv);
    if (debugger_h == 0) {
        while (true) syscall.thread_yield();
    }

    // Phase 2: tell the debugger where our symbols live at runtime.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call(
        debugger_h,
        &.{
            protocol.header(@intFromEnum(protocol.DbgVerb.hello), 0),
            @intFromPtr(&debuggee_slide_anchor),
            @intFromPtr(&bp_stop_1),
            @intFromPtr(&bp_stop_2),
            @intFromPtr(&bp_stop_3),
        },
        &reply,
    );

    // Phase 3: hand the debugger our HANDLE_SELF with the fault_handler
    // ProcessHandleRights bit so subsequent faults we raise (#BP on int3
    // / brk #0) are delivered to the debugger's fault box instead of
    // killing us. §2.12.3 describes the atomic installation.
    const fh_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_call_cap(debugger_h, &.{ 0, fh_rights }, &reply);

    // Phase 4: steady-state workload. Loop forever hitting each bp_stop.
    var tick: u64 = 0;
    while (true) : (tick +%= 1) {
        bp_stop_1();
        bp_stop_2();
        bp_stop_3();
        bp_stop_4();
    }
}

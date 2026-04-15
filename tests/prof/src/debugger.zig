//! Root-side driver for the debugger scenario.
//!
//! Spawns child_debugger and child_debuggee, then uses one ipc_call_cap
//! to hand the debuggee a handle to the debugger. The two children take
//! it from there — debuggee initiates a cap-transfer to hand
//! fault_handler off to the debugger, then enters its bp_stop loop.
//!
//! Root itself has no further work once the handoff is complete; it
//! suspends its own thread so the kprof trace isn't dominated by a
//! yield-loop from the driver process.

const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

pub fn main(_: u64) void {
    // Spawn debugger first so it's already parked in ipc_recv by the
    // time the debuggee comes up and tries to talk to it.
    const debugger_rights = (perms.ProcessRights{}).bits();
    const dbg_rc = syscall.proc_create(
        @intFromPtr(children.child_debugger.ptr),
        children.child_debugger.len,
        debugger_rights,
    );
    if (dbg_rc < 0) {
        while (true) syscall.thread_yield();
    }
    const debugger_h: u64 = @bitCast(dbg_rc);

    // Spawn debuggee with fault_handler in its own ProcessRights so it
    // can self-transfer that bit to the debugger via ipc_call_cap (see
    // §2.12.3). Without the bit on slot 0 the atomic install would
    // reject the transfer.
    const debuggee_rights = (perms.ProcessRights{ .fault_handler = true }).bits();
    const dee_rc = syscall.proc_create(
        @intFromPtr(children.child_debuggee.ptr),
        children.child_debuggee.len,
        debuggee_rights,
    );
    if (dee_rc < 0) {
        while (true) syscall.thread_yield();
    }
    const debuggee_h: u64 = @bitCast(dee_rc);

    // Cap-transfer the debugger handle into the debuggee's perm table
    // with just send_words + send_process so it's a routing handle, not
    // one carrying any elevated rights.
    const xfer_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .send_process = true,
    }).bits();
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(
        debuggee_h,
        &.{ debugger_h, xfer_rights },
        &reply,
    );

    // Suspend self so the trace isn't drowned by a yield-loop — the
    // debugger and debuggee run forever until an external timeout
    // kills the VM.
    const self_rc = syscall.thread_self();
    if (self_rc > 0) {
        _ = syscall.thread_suspend(@bitCast(self_rc));
    }
    while (true) syscall.thread_yield();
}

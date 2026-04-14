const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// kprof workload — drives sys_ipc_call / sys_ipc_recv / sys_ipc_reply
/// in a tight ping-pong loop against a single spawned child. proc_create
/// fires once during startup; the steady-state trace is dominated by IPC.
pub fn main(_: u64) void {
    const child_rights = (perms.ProcessRights{}).bits();
    const ch_rc: i64 = syscall.proc_create(
        @intFromPtr(children.child_ipc_echo.ptr),
        children.child_ipc_echo.len,
        child_rights,
    );
    if (ch_rc < 0) {
        while (true) syscall.thread_yield();
    }
    const child_handle: u64 = @bitCast(ch_rc);

    var counter: u64 = 0;
    while (true) {
        var reply: syscall.IpcMessage = .{};
        const rc = syscall.ipc_call(child_handle, &.{counter}, &reply);
        if (rc != 0) {
            syscall.thread_yield();
            continue;
        }
        counter = reply.words[0];
    }
}

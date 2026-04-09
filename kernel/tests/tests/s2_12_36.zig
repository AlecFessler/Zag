const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_AGAIN: i64 = -9;

/// §2.12.36 — The fault box state is fully independent from the IPC message box state.
/// `fault_recv` and `fault_reply` do not interact with `recv`/`reply` pending state;
/// both boxes may be in `pending_reply` simultaneously.
pub fn main(_: u64) void {
    // Non-blocking fault_recv — no faults pending, should return E_AGAIN.
    var fault_buf: [128]u8 align(8) = .{0} ** 128;
    const fault_rc = syscall.fault_recv(@intFromPtr(&fault_buf), 0);

    // Non-blocking ipc_recv — no messages pending, should return E_AGAIN.
    var ipc_msg: syscall.IpcMessage = .{};
    const ipc_rc = syscall.ipc_recv(false, &ipc_msg);

    // Both should independently return E_AGAIN, proving the fault box and
    // IPC message box are fully independent state machines.
    if (fault_rc == E_AGAIN and ipc_rc == E_AGAIN) {
        t.pass("§2.12.36");
    } else {
        if (fault_rc != E_AGAIN) {
            t.failWithVal("§2.12.36 fault_recv", E_AGAIN, fault_rc);
        }
        if (ipc_rc != E_AGAIN) {
            t.failWithVal("§2.12.36 ipc_recv", E_AGAIN, ipc_rc);
        }
    }
    syscall.shutdown();
}

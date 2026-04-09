const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const E_PERM: i64 = -2;

/// §2.12.32 — `fault_set_thread_mode` requires that the calling process holds `fault_handler` for the owning process of the target thread (the thread handle appears in the caller's perm table as a thread-type entry belonging to a process whose `fault_handler_proc == caller`).
/// for the owning process of the target thread. Returns `E_PERM` otherwise.
pub fn main(_: u64) void {
    // Get our own thread handle via thread_self.
    const self_handle = syscall.thread_self();
    if (self_handle < 0) {
        t.fail("§2.12.32 thread_self failed");
        syscall.shutdown();
    }

    // We are NOT an external fault handler for ourselves (we self-handle).
    // Calling fault_set_thread_mode with our own thread handle should return E_PERM
    // because the caller does not hold fault_handler for the owning process
    // of the target thread via an external fault_handler relationship.
    const rc = syscall.fault_set_thread_mode(@bitCast(self_handle), syscall.FAULT_MODE_STOP_ALL);
    t.expectEqual("§2.12.32", E_PERM, rc);
    syscall.shutdown();
}

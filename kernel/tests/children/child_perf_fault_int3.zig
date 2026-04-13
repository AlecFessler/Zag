const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;

/// Fault-cycle benchmark target. Cap-transfers `fault_handler` to the
/// parent so breakpoint faults route there, then loops executing `int3`.
/// Each int3 fires a trap the parent receives via `fault_recv`, replies
/// with `FAULT_RESUME`, and the child re-enters the loop.
///
/// Unlike the PMU-overflow children, this is single-threaded — a
/// synchronous breakpoint fault with an external handler is delivered
/// correctly for single-thread processes (see s4_1_106 and
/// child_int3_after_transfer). The park-thread workaround is only
/// required for async PMU-overflow faults.
pub fn main(_: u64) void {
    // Pin to same core as parent so REALTIME-priority parent preempts
    // us immediately after each fault_reply.
    _ = syscall.set_affinity(1);

    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    const fh_rights = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ 0, fh_rights });

    while (true) {
        asm volatile ("int3" ::: .{ .memory = true });
    }
}

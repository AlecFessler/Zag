const lib = @import("lib");

const syscall = lib.syscall;

/// Child spawned without any PMU-related rights. Calls `pmu_info`
/// (§4.50.2 says the syscall is callable by any process regardless
/// of rights) and reports the return code to the parent.
pub fn main(_: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    var info: syscall.PmuInfo = undefined;
    const rc = syscall.pmu_info(@intFromPtr(&info));
    _ = syscall.ipc_reply(&.{@bitCast(rc)});
}

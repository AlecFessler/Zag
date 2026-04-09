const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Receives device via IPC on first boot, then crashes in a hot loop (restarts repeatedly).
/// Device should persist across restarts because mid-restart is alive.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        // First boot: receive device handle via IPC cap transfer.
        var msg: syscall.IpcMessage = .{};
        _ = syscall.ipc_recv(true, &msg);
        _ = syscall.ipc_reply(&.{});
    }

    // Crash via UD2 — triggers restart, device should persist.
    asm volatile ("ud2");
}

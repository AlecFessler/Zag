const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// First boot: pins itself, then crashes (ud2). Restarts.
/// Second boot: checks perm_view for thread pin state and device entries,
/// reports counts via IPC. After restart, the thread should NOT be pinned
/// (field1 == 0 on the thread entry).
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        // First boot: receive device handle via IPC cap transfer.
        var msg: syscall.IpcMessage = .{};
        _ = syscall.ipc_recv(true, &msg);
        _ = syscall.ipc_reply(&.{});

        // Pin ourselves on core 1.
        _ = syscall.set_affinity(0x2);
        syscall.thread_yield();
        _ = syscall.set_priority(syscall.PRIORITY_PINNED);

        // Crash via UD2 — triggers restart.
        asm volatile ("ud2");
    }

    // Second+ boot: check that pin state was cleared (field1 == 0 on our thread entry).
    // The thread entry for the main thread is always at a known position; we look for
    // the self handle.
    const self_handle: u64 = @bitCast(syscall.thread_self());
    var pinned_after_restart: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_THREAD and entry.handle == self_handle) {
            if (entry.field1 != 0) {
                pinned_after_restart = 1;
            }
            break;
        }
    }

    // Also check for device entries (should persist).
    var device_count: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            device_count += 1;
        }
    }

    // Report via IPC: word0 = pinned_after_restart (0 = good), word1 = device_count
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{ pinned_after_restart, device_count });
}

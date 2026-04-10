const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const ENTRY_TYPE_CORE_PIN: u8 = 4;

/// First boot: pins itself, then crashes (ud2). Restarts.
/// Second boot: receives device via IPC on first boot (already done),
/// checks perm_view for core_pin entries and reports count via IPC.
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

    // Second+ boot: check for core_pin entries in our perm_view.
    var core_pin_count: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == ENTRY_TYPE_CORE_PIN) {
            core_pin_count += 1;
        }
    }

    // Also check for device entries (should persist).
    var device_count: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            device_count += 1;
        }
    }

    // Report via IPC: word0 = core_pin_count, word1 = device_count
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{ core_pin_count, device_count });
}

const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives device via cap transfer, tries dma_map, reports result via IPC.
pub fn main(perm_view_addr: u64) void {
    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Recv device via cap transfer
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});

    // Find device in our perm view
    var dev_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = entry.handle;
            break;
        }
    }

    // Create SHM for DMA
    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights)));

    const result = syscall.dma_map(dev_handle, shm_h);

    // Report result via IPC
    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);
    _ = syscall.ipc_reply(&.{@bitCast(result)});
}

const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives device via cap transfer, tries mem_mmio_map, reports result via IPC.
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

    // Create VM reservation with mmio flag
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .mmio = true }).bits();
    const vm = syscall.mem_reserve(0, 4096, vm_rights);

    var result: i64 = undefined;
    if (vm.val < 0) {
        result = vm.val;
    } else {
        result = syscall.mem_mmio_map(dev_handle, @bitCast(vm.val), 0);
    }

    // Report result via IPC
    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);
    _ = syscall.ipc_reply(&.{@bitCast(result)});
}

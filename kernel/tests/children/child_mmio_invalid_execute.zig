const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives MMIO device via cap transfer, maps it read+write (no execute),
/// then jumps to the MMIO mapping → invalid_execute.
pub fn main(perm_view_addr: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var dev_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = entry.handle;
            break;
        }
    }
    if (dev_handle == 0) return;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .mmio = true,
    }).bits();
    const vm = syscall.vm_reserve(0, 4096, vm_rights);
    if (vm.val < 0) return;
    if (syscall.mmio_map(dev_handle, @bitCast(vm.val), 0) != 0) return;

    const func: *const fn () void = @ptrFromInt(vm.val2);
    func();
}

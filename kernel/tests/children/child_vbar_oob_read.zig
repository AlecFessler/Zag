const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives PIO device via cap transfer, maps it as a virtual BAR, then
/// reads from an offset beyond port_count. The kernel should kill this
/// process with `invalid_read`.
pub fn main(perm_view_addr: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var dev_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION and entry.deviceType() == 1) {
            dev_handle = entry.handle;
            break;
        }
    }
    if (dev_handle == 0) return;

    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .mmio = true }).bits();
    const vm = syscall.mem_reserve(0, 4096, vm_rights);
    if (vm.val < 0) return;
    if (syscall.mem_mmio_map(dev_handle, @bitCast(vm.val), 0) != 0) return;

    const bar_base: u64 = vm.val2;

    // Access at offset 4095 (PAGE_SIZE - 1), well beyond any reasonable
    // port_count (AHCI PIO BAR is 32 ports). Should trigger invalid_read.
    const ptr: *volatile u8 = @ptrFromInt(bar_base + 4095);
    _ = ptr.*;
}

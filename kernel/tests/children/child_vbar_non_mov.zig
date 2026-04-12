const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Receives PIO device via cap transfer, maps it as a virtual BAR, then
/// executes a non-MOV instruction (INC) on the mapped address. The kernel
/// should kill this process with `protection_fault`.
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

    // Execute a non-MOV instruction (INC) on the virtual BAR address.
    // The kernel should detect this is not a MOV and kill with protection_fault.
    asm volatile ("incb (%%rax)"
        :
        : [addr] "{rax}" (bar_base),
        : .{ .memory = true });
}

const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Grandchild used by the §4.21.3 recursive `disable_restart` test.
///
/// On first boot, receives an SHM capability via IPC from its parent
/// (the intermediate spawner). On restart, the SHM persists in its perm
/// table so it skips the recv. Either way it maps the SHM, increments a
/// u64 counter stored in the SHM's trailing page, and exits — which, while
/// restart is still enabled, causes the kernel to restart it and repeat.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const self_entry = view[0];
    const restart_count = self_entry.processRestartCount();

    if (restart_count == 0) {
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;
        _ = syscall.ipc_reply(&.{});
    }

    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }
    if (shm_handle == 0 or shm_size == 0) return;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @bitCast(vm_result.val), 0) != 0) return;

    // Counter lives in the first u64 of the trailing control page.
    const counter: *u64 = @ptrFromInt(vm_result.val2 + shm_size - syscall.PAGE4K);
    _ = @atomicRmw(u64, counter, .Add, 1, .seq_cst);
}

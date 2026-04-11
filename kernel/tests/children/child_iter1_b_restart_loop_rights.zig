const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Helper for §2.6.15. On every boot (first and every restart) this child:
///   1. Reads its own view[0].rights (ProcessRights).
///   2. Appends a record (restart_count, rights) to SHM.
///   3. Increments the SHM counter and wakes any parent blocked on it.
///   4. Voluntarily exits — since the process is restartable this produces
///      another restart and another iteration.
///
/// The parent spawns this child with the SHM pre-mapped and transferred on
/// first boot. After the child's first run we send it nothing further; all
/// subsequent iterations re-discover the SHM slot from the persisted perm
/// table.
///
/// SHM layout (one page):
///   0  : iteration_count (u64) — also the futex wake cell for the parent
///   8  : records[MAX] of u64, each = rights_u16 | (restart_count_u16<<16)
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        // First boot — receive SHM via IPC.
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;
        _ = syscall.ipc_reply(&.{});
    }

    // Find SHM in persisted perm view.
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }
    if (shm_handle == 0) return;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;

    const base: u64 = vm_result.val2;
    const iter_ptr: *u64 = @ptrFromInt(base + 0);
    const self_rights: u16 = view[0].rights;
    const iter: u64 = iter_ptr.*;
    if (iter < 32) {
        const rec_ptr: *u64 = @ptrFromInt(base + 8 + iter * 8);
        rec_ptr.* = @as(u64, self_rights) | (@as(u64, restart_count) << 32);
    }
    iter_ptr.* = iter + 1;
    _ = syscall.futex_wake(iter_ptr, 1);

    // Voluntary exit → restart.
}

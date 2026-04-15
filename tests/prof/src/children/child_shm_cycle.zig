const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const PAGE_SIZE: u64 = 4096;

/// shm_cycle child — each iteration: ipc_recv to receive a freshly-
/// created SHM handle via cap transfer, ipc_reply immediately to
/// unblock the parent (single synchronization point), then reserve a
/// VM range, map the SHM, touch every page, unmap, and release both
/// the VM reservation and the SHM handle in parallel with the parent.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();

    while (true) {
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;

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

        if (syscall.ipc_reply(&.{}) != 0) return;

        const vm = syscall.mem_reserve(0, shm_size, vm_rights);
        if (vm.val < 0) return;
        const vm_handle: u64 = @bitCast(vm.val);

        if (syscall.mem_shm_map(shm_handle, vm_handle, 0) != 0) return;

        const base: [*]volatile u8 = @ptrFromInt(vm.val2);
        var off: u64 = 0;
        while (off < shm_size) {
            base[off] = 1;
            off += PAGE_SIZE;
        }

        _ = syscall.mem_unmap(vm_handle, 0, shm_size);
        _ = syscall.revoke_perm(vm_handle);
        _ = syscall.revoke_perm(shm_handle);
    }
}

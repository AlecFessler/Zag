const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

pub fn main(perm_view_addr: u64) void {
    // Broadcast with a known payload
    const rc = syscall.broadcast_syscall(0xBEEF);
    if (rc != 0) return;

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Wait for parent to grant us an SHM handle
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    var attempts: u32 = 0;
    while (attempts < 50_000) : (attempts += 1) {
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
                shm_handle = entry.handle;
                shm_size = entry.field0;
                break;
            }
        }
        if (shm_handle != 0) break;
        syscall.thread_yield();
    }

    if (shm_handle == 0 or shm_size == 0) return;

    // Map the SHM and write a sentinel value
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;

    const map_rc = syscall.shm_map(shm_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) return;

    const ptr: *u64 = @ptrFromInt(vm_result.val2);
    ptr.* = 0xCAFE;
    _ = syscall.futex_wake(@ptrFromInt(vm_result.val2), 1);
}

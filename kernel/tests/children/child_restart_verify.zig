const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    var has_vm_res = false;
    var shm_count: u32 = 0;

    var attempts: u32 = 0;
    while (attempts < 50_000) : (attempts += 1) {
        shm_handle = 0;
        shm_size = 0;
        has_vm_res = false;
        shm_count = 0;
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
                if (shm_handle == 0) {
                    shm_handle = entry.handle;
                    shm_size = entry.field0;
                }
                shm_count += 1;
            }
            if (entry.entry_type == pv.ENTRY_TYPE_VM_RESERVATION) {
                has_vm_res = true;
            }
        }
        if (shm_handle != 0) break;
        syscall.thread_yield();
    }

    if (shm_handle == 0 or shm_size == 0) return;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;

    const map_rc = syscall.shm_map(shm_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) return;

    const base = vm_result.val2;
    const run_counter: *volatile u64 = @ptrFromInt(base);
    const run_count = run_counter.*;

    const shm_count_slot: *volatile u64 = @ptrFromInt(base + 8 + run_count * 16);
    const vm_res_slot: *volatile u64 = @ptrFromInt(base + 16 + run_count * 16);

    shm_count_slot.* = shm_count;
    vm_res_slot.* = if (has_vm_res) 1 else 0;

    run_counter.* = run_count + 1;
    _ = syscall.futex_wake(@ptrFromInt(base), 1);
}

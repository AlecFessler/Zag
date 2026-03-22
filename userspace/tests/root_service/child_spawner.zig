const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 64;

pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

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

    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .execute = true, .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;

    const map_rc = syscall.shm_map(shm_handle, @intCast(vm_result.val), 0);
    if (map_rc != 0) return;

    const elf_ptr = vm_result.val2;
    const elf_bytes: [*]const u8 = @ptrFromInt(elf_ptr);

    const signal_ptr: *volatile u64 = @ptrFromInt(elf_ptr + shm_size - 8);

    const child_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const child_handle = syscall.proc_create(@intFromPtr(elf_bytes), shm_size - syscall.PAGE4K, child_rights);

    if (child_handle > 0) {
        signal_ptr.* = 1;
    } else {
        signal_ptr.* = 0xDEAD;
    }
    _ = syscall.futex_wake(@ptrCast(@volatileCast(signal_ptr)), 1);
}

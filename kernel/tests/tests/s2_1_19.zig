const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.19 — Each entry has a type field: `process`, `vm_reservation`, `shared_memory`, `device_region`, `core_pin`, or `dead_process`.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    // Slot 0 = process (HANDLE_SELF).
    const has_process = view[0].entry_type == perm_view.ENTRY_TYPE_PROCESS;
    // Create a VM reservation → vm_reservation type.
    const rw = perms.VmReservationRights{ .read = true, .write = true };
    const vm = syscall.vm_reserve(0, 4096, rw.bits());
    const vm_handle: u64 = @bitCast(vm.val);
    var has_vm = false;
    for (0..128) |i| {
        if (view[i].handle == vm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_VM_RESERVATION) {
            has_vm = true;
            break;
        }
    }
    // Create SHM → shared_memory type.
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(4096, shm_rights.bits())));
    var has_shm = false;
    for (0..128) |i| {
        if (view[i].handle == shm_handle and view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            has_shm = true;
            break;
        }
    }
    // Device region entries should exist from boot.
    var has_device = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            has_device = true;
            break;
        }
    }
    // Pin exclusive → core_pin type.
    _ = syscall.set_affinity(0x2);
    syscall.thread_yield();
    const pin_ret = syscall.pin_exclusive();
    var has_core_pin = false;
    if (pin_ret > 0) {
        const pin_handle: u64 = @bitCast(@as(i64, pin_ret));
        for (0..128) |i| {
            if (view[i].handle == pin_handle and view[i].entry_type == perm_view.ENTRY_TYPE_CORE_PIN) {
                has_core_pin = true;
                break;
            }
        }
        _ = syscall.revoke_perm(pin_handle);
    }
    // Spawn a child that exits immediately → dead_process type.
    const child_rights = perms.ProcessRights{};
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_exit.ptr),
        children.child_exit.len,
        child_rights.bits(),
    )));
    var child_slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == ch) {
            child_slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        if (view[child_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) break;
        syscall.thread_yield();
    }
    const has_dead = view[child_slot].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS;
    if (has_process and has_vm and has_shm and has_device and has_core_pin and has_dead) {
        t.pass("§2.1.19");
    } else {
        t.fail("§2.1.19");
    }
    syscall.shutdown();
}

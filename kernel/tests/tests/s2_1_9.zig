const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.9 — Device handle return skips zombie ancestors.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Find a device handle and save its identity.
    var dev_handle: u64 = 0;
    var dev_field0: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = view[i].handle;
            dev_field0 = view[i].field0;
            break;
        }
    }

    // Setup: root → mid (child_spawner_device) → grandchild (child_exit).
    // Mid receives SHM, spawns grandchild, then receives device, then exits.
    // Mid becomes zombie (has grandchild). Device return should skip zombie mid → root.

    // Prepare child_sleep ELF in SHM for child_spawner_device to spawn.
    // Use child_sleep (not child_exit) so the grandchild is guaranteed alive
    // when mid exits, making mid genuinely a zombie.
    const elf = children.child_sleep;
    const elf_pages = (elf.len + 4095) / 4096;
    const shm_size = (elf_pages + 1) * 4096;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_h: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, shm_size, vm_rw_s.bits());
    const vm_h: u64 = @bitCast(vm.val);
    _ = syscall.shm_map(shm_h, vm_h, 0);
    const dst: [*]u8 = @ptrFromInt(vm.val2);
    for (0..elf.len) |i| dst[i] = elf[i];

    // Spawn child_spawner_device with device_own + spawn_process.
    const child_rights = perms.ProcessRights{ .spawn_thread = true, .spawn_process = true, .mem_reserve = true, .shm_create = true, .device_own = true };
    const mid_h: u64 = @bitCast(@as(i64, syscall.proc_create(@intFromPtr(children.child_spawner_device.ptr), children.child_spawner_device.len, child_rights.bits())));

    // 1st IPC: send SHM with child_exit ELF.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(mid_h, &.{ shm_h, shm_rights.bits() }, &reply);

    // Wait for grandchild spawned signal.
    const signal_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 8);
    t.waitUntilNonZero(signal_ptr);

    // 2nd IPC: send device handle to mid.
    const dev_drights = perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true };
    _ = syscall.ipc_call_cap(mid_h, &.{ dev_handle, dev_drights.bits() }, &reply);

    // Mid now holds device and exits → becomes zombie (has grandchild).
    // Device return walks up: mid (zombie, skip) → root.
    // Wait for device to reappear in our perm_view.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        for (0..128) |i| {
            if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].field0 == dev_field0) {
                t.pass("§2.1.9");
                syscall.shutdown();
            }
        }
        syscall.thread_yield();
    }

    t.fail("§2.1.9");
    syscall.shutdown();
}

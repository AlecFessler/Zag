const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.1.4 — Zombies hold no resources (no VM reservations, SHM, or device handles).
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Grab the AHCI MMIO device — stable on the QEMU q35 test rig.
    const dev = t.requireMmioDevice(view, "§2.1.4");
    const dev_handle = dev.handle;
    const dev_field0 = dev.field0;

    // Use child_spawner_device: it receives SHM (spawns grandchild), then receives
    // a device handle, then exits. Since it has a grandchild, it becomes a zombie.
    // On zombie cleanup, the device should return to us (proving resource release).
    const elf = children.child_sleep;
    const elf_pages = (elf.len + 4095) / 4096;
    const shm_size = (elf_pages + 1) * 4096;
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rw_s = perms.VmReservationRights{ .read = true, .write = true, .shareable = true };
    const vm = syscall.vm_reserve(0, shm_size, vm_rw_s.bits());
    _ = syscall.shm_map(shm_handle, @bitCast(vm.val), 0);
    const dst: [*]u8 = @ptrFromInt(vm.val2);
    for (0..elf.len) |i| dst[i] = elf[i];

    // Spawn child_spawner_device (will become zombie after spawning grandchild + receiving device).
    const child_rights = perms.ProcessRights{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .shm_create = true,
        .device_own = true,
    };
    const child_handle: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_spawner_device.ptr),
        children.child_spawner_device.len,
        child_rights.bits(),
    )));

    // 1st IPC: send SHM with grandchild ELF.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(child_handle, &.{ shm_handle, shm_rights.bits() }, &reply);

    // Wait for grandchild to be spawned.
    const signal_ptr: *u64 = @ptrFromInt(vm.val2 + shm_size - 8);
    t.waitUntilNonZero(signal_ptr);

    // 2nd IPC: transfer device to child via cap transfer.
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    _ = syscall.ipc_call_cap(child_handle, &.{ dev_handle, dev_rights }, &reply);

    // child_spawner_device exits after receiving device → becomes zombie (has grandchild).
    // §2.1.4: zombie holds no resources → device should return to us.

    // Wait for child to become zombie.
    var attempts: u32 = 0;
    while (attempts < 100000) : (attempts += 1) {
        var found_dead = false;
        for (0..128) |i| {
            if (view[i].handle == child_handle and view[i].entry_type == perm_view.ENTRY_TYPE_DEAD_PROCESS) {
                found_dead = true;
                break;
            }
        }
        if (found_dead) break;
        syscall.thread_yield();
    }

    // Verify device returned to us (zombie released it).
    var device_returned = false;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and view[i].field0 == dev_field0) {
            device_returned = true;
            break;
        }
    }

    if (device_returned) {
        t.pass("§2.1.4");
    } else {
        t.fail("§2.1.4");
    }
    syscall.shutdown();
}

const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// 1st recv: SHM with grandchild ELF.
/// 2nd recv: device handle (cap transfer).
/// Spawns grandchild (child_recv_device_exit), transfers device to grandchild.
/// Then fills own perm table with mem_reserve calls.
/// Grandchild exits → device return walks up → this process table is full → skip to parent.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // 1st recv: SHM with grandchild ELF.
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    _ = syscall.ipc_reply(&.{});

    // Find SHM.
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

    // Map SHM.
    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .execute = true, .shareable = true }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    _ = syscall.mem_shm_map(shm_handle, @bitCast(vm_result.val), 0);
    const elf_ptr = vm_result.val2;

    // Spawn grandchild (child_recv_device_exit).
    const child_rights = (perms.ProcessRights{ .spawn_thread = true, .device_own = true }).bits();
    const gc = syscall.proc_create(elf_ptr, shm_size - syscall.PAGE4K, child_rights);
    if (gc < 0) return;
    const gc_handle: u64 = @bitCast(gc);

    // 2nd recv: device handle from parent (before filling table — need a free slot).
    var msg2: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg2);
    _ = syscall.ipc_reply(&.{});

    // Find device in our perm view.
    var dev_handle: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_DEVICE_REGION) {
            dev_handle = entry.handle;
            break;
        }
    }
    if (dev_handle == 0) return;

    // Fill all remaining slots except 1 (for device transfer to work).
    const fill_rights = (perms.VmReservationRights{ .read = true, .write = true }).bits();
    var filled: u32 = 0;
    while (filled < 200) : (filled += 1) {
        const r = syscall.mem_reserve(0, 4096, fill_rights);
        if (r.val < 0) break;
    }

    // Transfer device to grandchild (child_recv_device_wait). Exclusive: removes from our
    // table (frees 1 slot), inserts into grandchild.
    const dev_rights = (perms.DeviceRegionRights{ .map = true, .grant = true, .dma = true }).bits();
    var gc_reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(gc_handle, &.{ dev_handle, dev_rights }, &gc_reply);

    // Fill the slot freed by device transfer.
    _ = syscall.mem_reserve(0, 4096, fill_rights);

    // Now tell grandchild to exit (2nd call triggers exit).
    _ = syscall.ipc_call(gc_handle, &.{}, &gc_reply);

    // Grandchild has now exited. Its entry in our table → dead_process (still occupies slot).
    // Table remains 128/128. Device return can't insert → walks to root.

    // Signal parent.
    const signal_ptr: *u64 = @ptrFromInt(elf_ptr + shm_size - 8);
    signal_ptr.* = 1;
    _ = syscall.futex_wake(signal_ptr, 1);

    // Stay alive — block on recv.
    var msg3: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg3);
}

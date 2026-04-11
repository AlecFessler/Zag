const children = @import("embedded_children");
const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

/// §2.6.14 — Process tree position and children persist across restart.
///
/// We spawn a restartable "parent" child that itself spawns a grandchild
/// (using child_sleep as the grandchild ELF shipped via SHM), records the
/// grandchild handle id, and then stack-overflows to force a restart. After
/// restart, the parent scans its perm view for the grandchild and reports
/// it back on a second IPC call. The test asserts:
///   1. The parent restarted (restart_count > 0).
///   2. The grandchild handle id we observed on first boot is still visible
///      in the parent's perm view after restart.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Build an SHM with the grandchild ELF (child_sleep) followed by a few
    // scratch pages. Layout: [ELF bytes][pad][u64 scratch holes at the tail].
    const gc_elf = children.child_sleep;
    const elf_pages = (gc_elf.len + 4095) / 4096;
    const shm_pages = elf_pages + 2;
    const shm_size: u64 = shm_pages * 4096;

    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm_handle: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(shm_size, shm_rights.bits())));

    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, shm_size, vm_rights);
    const vm_h: u64 = @bitCast(vm.val);
    _ = syscall.mem_shm_map(shm_handle, vm_h, 0);
    const base = vm.val2;
    // Copy grandchild ELF into the SHM.
    const dst: [*]u8 = @ptrFromInt(base);
    for (0..gc_elf.len) |i| dst[i] = gc_elf[i];
    // Zero the scratch cell at tail-16 where the restartable parent will
    // record the grandchild handle on first boot.
    const gc_slot_local: *volatile u64 = @ptrFromInt(base + shm_size - 16);
    gc_slot_local.* = 0;

    // Spawn restartable parent.
    const parent_rights = perms.ProcessRights{
        .spawn_thread = true,
        .spawn_process = true,
        .mem_reserve = true,
        .mem_shm_create = true,
        .restart = true,
    };
    const parent_h: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_grandparent_restart.ptr),
        children.child_grandparent_restart.len,
        parent_rights.bits(),
    )));

    // Transfer the SHM to the parent (which will spawn the grandchild).
    var reply1: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(parent_h, &.{ shm_handle, shm_rights.bits() }, &reply1);

    // Capture grandchild handle id the restartable parent recorded.
    const gc_id_first_boot = gc_slot_local.*;

    // Wait for the parent to actually restart (stack overflow fault triggers
    // restart since the parent holds `restart` right).
    var slot: usize = 0;
    for (0..128) |i| {
        if (view[i].handle == parent_h) {
            slot = i;
            break;
        }
    }
    var attempts: u32 = 0;
    while (attempts < 500000) : (attempts += 1) {
        if (view[slot].processRestartCount() > 0) break;
        syscall.thread_yield();
    }
    if (view[slot].processRestartCount() == 0) {
        t.fail("§2.6.14 parent never restarted");
        syscall.shutdown();
    }

    // Second call — parent reports the process entry it still holds.
    var reply2: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(parent_h, &.{}, &reply2);
    const gc_id_after_restart = reply2.words[0];

    const restart_seen = view[slot].processRestartCount() > 0;
    const grandchild_persists = gc_id_first_boot != 0 and
        gc_id_first_boot == gc_id_after_restart;

    if (rc == 0 and restart_seen and grandchild_persists) {
        t.pass("§2.6.14");
    } else {
        t.fail("§2.6.14");
    }
    syscall.shutdown();
}

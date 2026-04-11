const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Restartable parent used by §2.6.14. On first boot: receive an SHM with
/// grandchild ELF, spawn the grandchild, write the grandchild handle id into
/// the SHM at offset 0 so the test root can observe it, then crash (stack
/// overflow). On restart: scan our perm view for a process entry that is
/// not slot 0, write that handle id at offset 8, and reply to the test via
/// IPC so the root can observe both.
fn recurse(depth: u64) u64 {
    if (depth == 0) return 0;
    var buf: [512]u8 = undefined;
    buf[0] = @truncate(depth);
    return buf[0] + recurse(depth - 1);
}

pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        // Receive SHM (grandchild ELF) via cap transfer.
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

        const vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .shareable = true,
        }).bits();
        const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
        if (vm_result.val < 0) return;
        if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;

        const base = vm_result.val2;
        // Spawn the grandchild from the ELF shipped in the SHM (first
        // shm_size - 2*PAGE4K bytes; last page reserved for scratch).
        const elf_len = shm_size - 2 * syscall.PAGE4K;
        const elf_ptr: [*]const u8 = @ptrFromInt(base);
        const gc_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
        const gc = syscall.proc_create(@intFromPtr(elf_ptr), elf_len, gc_rights);
        if (gc <= 0) return;
        const gc_handle: u64 = @bitCast(gc);

        // Record grandchild handle id at offset shm_size - 16.
        const gc_slot: *u64 = @ptrFromInt(base + shm_size - 16);
        gc_slot.* = gc_handle;
        _ = syscall.ipc_reply(&.{});

        // Crash to trigger restart.
        _ = recurse(100_000);
        return;
    }

    // Second boot: parent restarted, grandchild should still be in our perm
    // view. Receive parent's post-restart call and reply with the grandchild
    // handle we still hold.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    var gc_in_view: u64 = 0;
    var slot_idx: usize = 0;
    while (slot_idx < MAX_PERMS) : (slot_idx += 1) {
        if (slot_idx == 0) continue;
        const e = &view[slot_idx];
        if (e.entry_type == pv.ENTRY_TYPE_PROCESS and e.handle != 0) {
            gc_in_view = e.handle;
            break;
        }
    }
    _ = syscall.ipc_reply(&.{gc_in_view});
}

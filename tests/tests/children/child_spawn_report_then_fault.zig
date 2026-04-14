const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Like child_spawn_and_report but instead of parking, faults after
/// reporting the grandchild handle. Used by §2.6.31 to drive a non-recursive
/// kill (fault kill) of a non-restartable process that has a child — the
/// kernel should convert us to zombie (dead_process) and leave the
/// grandchild alive and still addressable via the handle we reported.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // 1. Receive SHM handle via IPC.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    // 2. Locate SHM in perm view.
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

    // 3. Map SHM, spawn grandchild from its ELF.
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    _ = syscall.mem_shm_map(shm_handle, @bitCast(vm_result.val), 0);

    const elf_ptr = vm_result.val2;
    const elf_bytes: [*]const u8 = @ptrFromInt(elf_ptr);
    const signal_ptr: *u64 = @ptrFromInt(elf_ptr + shm_size - 8);

    const gc_rights = (perms.ProcessRights{ .spawn_thread = true }).bits();
    const gc = syscall.proc_create(@intFromPtr(elf_bytes), shm_size - syscall.PAGE4K, gc_rights);
    if (gc <= 0) {
        signal_ptr.* = 0xDEAD;
        _ = syscall.futex_wake(signal_ptr, 1);
        return;
    }
    signal_ptr.* = 1;
    _ = syscall.futex_wake(signal_ptr, 1);

    // 4. Wait for parent to call us, transfer the grandchild handle back.
    var msg2: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg2) != 0) return;
    const gc_h: u64 = @bitCast(@as(i64, gc));
    const handle_rights = (perms.ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .grant = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ gc_h, handle_rights });

    // 5. Fault — triggers non-recursive fault kill. We're non-restartable
    // and have a living grandchild, so per §2.6.31 we convert to zombie.
    const p: *allowzero volatile u64 = @ptrFromInt(0x0);
    p.* = 0xDEADBEEF;
}

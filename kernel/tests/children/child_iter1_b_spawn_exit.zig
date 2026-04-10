const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// §2.6.31 helper. Non-recursive-kill variant: spawn a grandchild from an
/// ELF delivered via SHM, report the grandchild handle back to the parent
/// via cap transfer, then voluntarily exit via `thread_exit`. Since we are
/// non-restartable and still have a living child at exit time, the kernel
/// must convert our parent-view entry to `dead_process` (zombie) rather
/// than fully cleaning us up — and must leave the grandchild alive and
/// still addressable via the handle the parent received.
///
/// This differs from child_spawn_report_then_fault (which drives a fault
/// kill): voluntary exit exercises the "non-recursive kill" clause of
/// §2.6.31 without going through the fault path.
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
    const vm_result = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    _ = syscall.shm_map(shm_handle, @bitCast(vm_result.val), 0);

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

    // 4. Wait for parent's second call, transfer grandchild handle back.
    var msg2: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg2) != 0) return;
    const gc_h: u64 = @bitCast(@as(i64, gc));
    const handle_rights = (perms.ProcessHandleRights{
        .send_words = true,
        .send_shm = true,
        .grant = true,
    }).bits();
    _ = syscall.ipc_reply_cap(&.{ gc_h, handle_rights });

    // 5. Voluntary exit of the initial thread → process exit. Non-restartable
    //    + has a living child → per §2.6.31 we become a zombie (dead_process
    //    in parent's view); the grandchild stays alive.
    syscall.thread_exit();
}

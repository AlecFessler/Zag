const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Child used by §2.11.5 and §2.11.16 to observe "call is blocked on reply".
///
/// Protocol:
///   1. Recv initial setup message (carries SHM handle via cap transfer),
///      reply with empty payload.
///   2. Map the SHM.
///   3. Recv the real ipc_call from the parent (blocks the caller).
///   4. Set buf[0] = 1 ("received, about to delay before reply"). This is
///      the explicit sentinel the parent uses to know the caller is
///      sitting inside the kernel on its reply wait.
///   5. Yield many times to keep the caller blocked for an extended,
///      observable window.
///   6. Reply with words[0] + 1 so the parent can verify the reply actually
///      traveled back.
pub fn main(perm_view_addr: u64) void {
    // Setup recv — receive SHM handle via cap transfer, reply empty.
    var setup_msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &setup_msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
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
    const vm = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm.val < 0) return;
    if (syscall.shm_map(shm_handle, @intCast(vm.val), 0) != 0) return;

    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    // Real call from parent.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;

    // Signal: received, about to delay before replying.
    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1, .release);
    _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[0]))), 1);

    // Delay so the parent can observe the caller is still blocked.
    var i: u32 = 0;
    while (i < 500) : (i += 1) syscall.thread_yield();

    msg.words[0] += 1;
    _ = syscall.ipc_reply(msg.words[0..msg.word_count]);
}

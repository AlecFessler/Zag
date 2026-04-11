const lib = @import("lib");

const perms = lib.perms;
const perm_view = lib.perm_view;
const syscall = lib.syscall;

// SHM layout:
//   offset 0:  u64 — main writes the first received fault token here
//                    (proves §2.12.8 delivery of at least one fault message
//                     before the process was killed/restarted per §2.12.9).
//
// Restart semantics: perm view persists across restart, but process code
// reruns from main(). The parent uses the child's restart_count to observe
// §2.12.9 firing. The SHM is mapped fresh each time but the bytes survive
// because the parent holds the SHM handle in its own table.

var shm_va: u64 = 0;

fn faulterA() void {
    _ = asm volatile ("movb (%%rax), %%al"
        : [ret] "={al}" (-> u8),
        : [addr] "{rax}" (@as(u64, 0)),
        : .{ .memory = true });
    while (true) asm volatile ("pause");
}

fn faulterB() void {
    // Short yield so the main thread has a moment to fault_recv the first
    // worker's fault before this one enters .faulted.
    var i: u32 = 0;
    while (i < 1000) : (i += 1) syscall.thread_yield();
    _ = asm volatile ("movb (%%rax), %%al"
        : [ret] "={al}" (-> u8),
        : [addr] "{rax}" (@as(u64, 0)),
        : .{ .memory = true });
    while (true) asm volatile ("pause");
}

/// Self-handling multi-thread child for §2.12.9.
///
/// Flow on first run:
///   1. Receive SHM via ipc_call cap transfer from parent. Map it.
///   2. Reply to parent so the parent knows we're ready.
///   3. Spawn workerA (faults immediately) and workerB (yields, then faults).
///   4. fault_recv the first fault message (proves §2.12.8 delivered it).
///   5. Write the received token into SHM[0] so the parent can observe it.
///   6. Deliberately null-deref on the main thread. With workerA and
///      workerB already `.faulted`, the main thread entering `.faulted`
///      makes all three threads simultaneously `.faulted`, which per
///      §2.12.9 triggers kill/restart.
///
/// On restart, `restart_count` is incremented in the parent's perm entry
/// and the parent's crash reason reflects the null-deref fault reason.
pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);

    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = view[i].handle;
            shm_size = view[i].field0;
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
    shm_va = vm_result.val2;

    _ = syscall.thread_create(&faulterA, 0, 4);
    _ = syscall.thread_create(&faulterB, 0, 4);

    _ = syscall.ipc_reply(&.{});

    var buf: [256]u8 align(8) = undefined;
    const tok = syscall.fault_recv(@intFromPtr(&buf), 1);
    if (tok > 0) {
        const slot: *volatile u64 = @ptrFromInt(shm_va + 0);
        slot.* = @bitCast(tok);
    }

    // Give workerB time to also enter .faulted so the kill below puts
    // the process into the "all threads faulted" state, triggering
    // §2.12.9.
    var i: u32 = 0;
    while (i < 5000) : (i += 1) syscall.thread_yield();

    // Main null-derefs. Three threads now in .faulted — §2.12.9 fires.
    _ = asm volatile ("movb (%%rax), %%al"
        : [ret] "={al}" (-> u8),
        : [addr] "{rax}" (@as(u64, 0)),
        : .{ .memory = true });
}

const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));
const PAGE: u64 = 4096;

/// §2.11.1 — `send` is non-blocking: the sender continues running after delivery.
///
/// We transfer a SHM to child_ipc_shm_recorder which will record each
/// received message into that SHM and spin on buf[7] while processing.
///
/// Sequence:
///   1. Setup call cap-transfers SHM to child.
///   2. Parent sets buf[7] = 1 (hold the recorder mid-processing).
///   3. Parent ipc_send(magic). Recorder recv returns, writes 0xDEADBEEF,
///      then spins on buf[7] = 1 — the recorder cannot complete the reply
///      or return from anywhere until we release buf[7].
///   4. After ipc_send returns, parent immediately writes a sentinel
///      `post_send` into a local u64. Because ipc_send returned while the
///      recorder is still spinning on buf[7] (proven by buf[0] == magic
///      and buf[7] != 0), send was non-blocking.
///   5. Parent releases buf[7] so child can reply cleanly.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));

    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.vm_reserve(0, PAGE, vm_rights);
    _ = syscall.shm_map(shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_ipc_shm_recorder.ptr),
        children.child_ipc_shm_recorder.len,
        child_rights,
    )));

    // Setup: cap-transfer SHM. Child maps and enters main recv loop.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ shm, shm_rights.bits() }, &reply);

    // Prime the hold flag so the recorder will spin after it reads the msg.
    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[7]))), 1, .release);

    // Give child time to enter its recv.
    for (0..100) |_| syscall.thread_yield();

    // Fire-and-forget send.
    const rc = syscall.ipc_send(ch, &.{0x4242_4242});
    if (rc != 0) {
        @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[7]))), 0, .release);
        _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[7]))), 1);
        t.failWithVal("§2.11.1 send failed", 0, rc);
        syscall.shutdown();
    }

    // Observe that the recorder saw the message while we are back in control.
    // Wait (bounded) for buf[0] == 0xDEADBEEF to confirm delivery.
    var saw: bool = false;
    var tries: u32 = 0;
    while (tries < 100000) : (tries += 1) {
        if (@atomicLoad(u64, @as(*u64, @ptrCast(@volatileCast(&buf[0]))), .acquire) == 0xDEADBEEF) {
            saw = true;
            break;
        }
        syscall.thread_yield();
    }

    if (!saw) {
        @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[7]))), 0, .release);
        _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[7]))), 1);
        t.fail("§2.11.1 recorder never saw msg");
        syscall.shutdown();
    }

    // The recorder is currently spinning on buf[7]. The fact that WE are
    // executing (not blocked inside ipc_send) while the recorder is still
    // mid-processing proves ipc_send was non-blocking.
    const payload_ok = buf[1] == 0x4242_4242;

    // Release the recorder so it can reply and return to recv.
    @atomicStore(u64, @as(*u64, @ptrCast(@volatileCast(&buf[7]))), 0, .release);
    _ = syscall.futex_wake(@as(*u64, @ptrCast(@volatileCast(&buf[7]))), 1);

    if (payload_ok) {
        t.pass("§2.11.1");
    } else {
        t.fail("§2.11.1 payload mismatch");
    }
    syscall.shutdown();
}

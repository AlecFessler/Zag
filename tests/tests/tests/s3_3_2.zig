const children = @import("embedded_children");
const lib = @import("lib");

const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const PAGE: u64 = 4096;

/// §3.3.2 — `send` delivers payload to a receiver blocked on `recv`.
///
/// The child_ipc_shm_recorder writes the received first word into SHM so
/// we can assert the magic value `0x42` actually arrived.
pub fn main(_: u64) void {
    const shm_rights = perms.SharedMemoryRights{ .read = true, .write = true, .grant = true };
    const shm: u64 = @bitCast(@as(i64, syscall.shm_create_with_rights(PAGE, shm_rights.bits())));

    const vm_rights = (perms.VmReservationRights{ .read = true, .write = true, .shareable = true }).bits();
    const vm = syscall.mem_reserve(0, PAGE, vm_rights);
    _ = syscall.mem_shm_map(shm, @bitCast(vm.val), 0);
    const buf: [*]volatile u64 = @ptrFromInt(vm.val2);

    const child_rights = (perms.ProcessRights{ .mem_reserve = true }).bits();
    const ch: u64 = @bitCast(@as(i64, syscall.proc_create(
        @intFromPtr(children.child_ipc_shm_recorder.ptr),
        children.child_ipc_shm_recorder.len,
        child_rights,
    )));

    // Setup: cap-transfer SHM.
    var reply: syscall.IpcMessage = .{};
    _ = syscall.ipc_call_cap(ch, &.{ shm, shm_rights.bits() }, &reply);

    // Let child enter recv. On SMP, the recorder may not have re-entered
    // ipc_recv yet after replying to the setup call, so retry while
    // ipc_send returns E_AGAIN ("no receiver waiting").
    for (0..50) |_| syscall.thread_yield();

    var send_rc: i64 = 0;
    var send_tries: u32 = 0;
    while (send_tries < 10000) {
        send_rc = syscall.ipc_send(ch, &.{0x42});
        if (send_rc != -9) break;
        syscall.thread_yield();
        send_tries += 1;
    }
    if (send_rc != 0) {
        t.failWithVal("§3.3.2 send", 0, send_rc);
        syscall.shutdown();
    }

    // Wait for recorder to see the message.
    var tries: u32 = 0;
    while (tries < 100000) : (tries += 1) {
        if (@atomicLoad(u64, @as(*u64, @ptrCast(@volatileCast(&buf[0]))), .acquire) == 0xDEADBEEF) break;
        syscall.thread_yield();
    }

    const first_word = buf[1];
    if (first_word == 0x42) {
        t.pass("§3.3.2");
    } else {
        t.failWithVal("§3.3.2", 0x42, @bitCast(first_word));
    }
    syscall.shutdown();
}

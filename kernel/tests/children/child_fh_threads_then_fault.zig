const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

var parked: u64 align(8) = 0;
var started: u64 align(8) = 0;

fn parker() void {
    _ = @atomicRmw(u64, &started, .Add, 1, .release);
    _ = syscall.futex_wake(@ptrCast(&started), 1);
    _ = syscall.futex_wait(@ptrCast(&parked), 0, @bitCast(@as(i64, -1)));
}

/// §2.6.35 helper.
///
/// On first boot: reply to parent with HANDLE_SELF carrying fault_handler so
/// the parent becomes our external fault handler. Spawn two worker threads
/// that park in futex_wait. Wait for them to publish. Block on a second
/// recv so the parent can make a follow-up call telling us to proceed.
/// Then fault — the fault is routed to the parent (our fault handler). The
/// parent either replies FAULT_KILL, triggering restart (we have restart
/// right), or lets us die. Either way the per-thread handles in the parent
/// must be torn down and replaced with a single fresh initial thread.
///
/// On second boot (restart_count > 0): just wait for the parent's IPC and
/// reply with restart_count so parent can confirm we're the new instance.
pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;
        const rights: u64 = (perms.ProcessHandleRights{
            .send_words = true,
            .fault_handler = true,
        }).bits();
        _ = syscall.ipc_reply_cap(&.{ 0, rights });

        // Spawn two parker worker threads.
        _ = syscall.thread_create(&parker, 0, 4);
        _ = syscall.thread_create(&parker, 0, 4);
        while (@atomicLoad(u64, &started, .acquire) < 2) syscall.thread_yield();

        // Wait for "go" signal from parent.
        var msg2: syscall.IpcMessage = .{};
        _ = syscall.ipc_recv(true, &msg2);
        _ = syscall.ipc_reply(&.{});

        // Fault — the parent (our fault handler) will reply FAULT_KILL.
        const p: *allowzero volatile u64 = @ptrFromInt(0x0);
        p.* = 0xDEAD;
        return;
    }

    // Second boot.
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{restart_count});
}

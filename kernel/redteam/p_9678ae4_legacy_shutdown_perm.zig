// PoC for 9678ae4: legacy shutdown syscall bypassed permission check.
//
// Pre-patch: SyscallNum.shutdown dispatched directly to a noreturn
// sysShutdown() that called arch.shutdown() with no permission gate. Any
// process — including a child spawned with empty ProcessRights — could
// halt the entire machine.
//
// Post-patch: SyscallNum.shutdown is rerouted through sysSysPower(0),
// which checks the caller's slot-0 ProcessRights.power bit and returns
// E_PERM if missing. An unprivileged child can no longer power off the
// system.
//
// Differential design (per user instructions): the moment a vulnerable
// child actually calls shutdown the system halts and we lose all serial
// output, so we use a side-channel. The parent prints an optimistic
// "VULNERABLE" line BEFORE giving the child a chance to attack, then
// ipc_call's into the child. The child blocks in ipc_recv, accepts the
// call, then attempts the legacy shutdown syscall directly. Pre-patch
// the machine halts and the parent never returns from ipc_call, so the
// last line on serial is VULNERABLE. Post-patch the child receives
// E_PERM back from the syscall and ipc_reply's the rc to the parent,
// which then prints "PATCHED" and powers off cleanly.
//
//   Pre-patch run:
//     POC-9678ae4: starting
//     POC-9678ae4: VULNERABLE   <-- last line; system halts here
//
//   Post-patch run:
//     POC-9678ae4: starting
//     POC-9678ae4: VULNERABLE
//     POC-9678ae4: child shutdown rc=E_PERM
//     POC-9678ae4: PATCHED      <-- last line; parent shuts down cleanly
//
// The reader takes the LAST `POC-9678ae4:` line as the verdict, matching
// the convention used by the other red-team PoCs in this directory.

const lib = @import("lib");
const perms = lib.perms;
const syscall = lib.syscall;

const child_elf align(8) = @embedFile("zig-out/bin/child").*;

pub fn main(_: u64) void {
    syscall.write("POC-9678ae4: starting\n");

    // Spawn the child with COMPLETELY empty ProcessRights — in particular
    // no `power` bit, which is the right sysSysPower checks.
    const child_rights = (perms.ProcessRights{}).bits();
    const cr = syscall.proc_create(@intFromPtr(&child_elf), child_elf.len, child_rights);
    if (cr < 0) {
        syscall.write("POC-9678ae4: proc_create failed\n");
        syscall.shutdown();
    }

    // Yield a few times so the child reaches its first ipc_recv.
    var y: usize = 0;
    while (y < 4) {
        syscall.thread_yield();
        y += 1;
    }

    // Optimistic verdict: assume the worst. If the child successfully
    // shuts the machine down (pre-patch behavior), this is the last
    // POC-9678ae4 line that ever reaches the serial port and the harness
    // sees VULNERABLE. If the patch is in place we'll print PATCHED
    // below after the ipc_call returns with the child's reply.
    syscall.write("POC-9678ae4: VULNERABLE\n");

    // ipc_call into the child. Pre-patch, the child halts the machine
    // inside its raw shutdown syscall and we never return — the last
    // serial line is VULNERABLE above. Post-patch, the child gets E_PERM
    // back from shutdown and ipc_reply's a single word containing the
    // rc, so this call returns normally.
    var reply: syscall.IpcMessage = .{};
    const rrc = syscall.ipc_call(@intCast(cr), &.{}, &reply);
    if (rrc != syscall.E_OK) {
        syscall.write("POC-9678ae4: ipc_call failed\n");
        syscall.shutdown();
    }

    // Tag the rc the child saw with a single ASCII byte for logging.
    var rc_buf: [1]u8 = .{'?'};
    rc_buf[0] = switch (@as(i64, @bitCast(reply.words[0]))) {
        syscall.E_PERM => 'P',
        syscall.E_OK => 'O',
        else => '?',
    };
    syscall.write("POC-9678ae4: child shutdown rc=");
    syscall.write(&rc_buf);
    syscall.write("\n");

    if (@as(i64, @bitCast(reply.words[0])) == syscall.E_PERM) {
        syscall.write("POC-9678ae4: PATCHED\n");
    } else {
        // Child somehow returned but not with E_PERM — still vulnerable
        // in the sense that the patch's gate didn't fire. Re-emit the
        // VULNERABLE marker as the last line.
        syscall.write("POC-9678ae4: VULNERABLE (shutdown returned without E_PERM)\n");
    }

    syscall.shutdown();
}

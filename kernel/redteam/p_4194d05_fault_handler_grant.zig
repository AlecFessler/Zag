// PoC for 4194d05: transferCapability HANDLE_SELF fault_handler grant check.
//
// Pre-patch: transferCapability's HANDLE_SELF fault_handler path did not
// verify that the sender actually held ProcessRights.fault_handler on its
// slot 0 before granting the right. A child process with empty rights
// could install its parent as its own fault handler by ipc_reply_cap'ing
// HANDLE_SELF with the fault_handler bit set.
//
// Post-patch: transferCapability checks the sender's slot-0 fault_handler
// bit; missing → E_PERM.
//
// Differential: parent spawns a child with empty ProcessRights, child
// ipc_reply_cap's HANDLE_SELF with fault_handler=1, parent observes
// ipc_call return code. Pre-patch: E_OK (grant accepted). Post-patch:
// E_PERM.

const lib = @import("lib");
const syscall = lib.syscall;
const perms = lib.perms;

const child_elf align(8) = @embedFile("zig-out/bin/child").*;

pub fn main(_: u64) void {
    const child_rights = (perms.ProcessRights{}).bits(); // empty — no fault_handler
    const cr = syscall.proc_create(@intFromPtr(&child_elf), child_elf.len, child_rights);
    if (cr < 0) {
        syscall.write("POC-4194d05: proc_create failed\n");
        syscall.shutdown();
    }

    // Let the child reach ipc_recv.
    syscall.thread_yield();
    syscall.thread_yield();

    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(@intCast(cr), &.{}, &reply);

    if (rc == syscall.E_PERM) {
        syscall.write("POC-4194d05: PATCHED (grant rejected, E_PERM)\n");
    } else {
        syscall.write("POC-4194d05: VULNERABLE (grant accepted)\n");
    }
    syscall.shutdown();
}

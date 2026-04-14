// PoC for 35bf077: ProcessRights.vm_create permission gate.
//
// Pre-patch: vmCreate did not check any per-process right; any process
// could call vm_create and obtain a VM (subject only to hardware,
// vcpu_count, and perm-table room). In particular a child process spawned
// with empty ProcessRights could still create a VM and gain control over
// VMX state.
//
// Post-patch: vmCreate checks slot-0 ProcessRights.vm_create and returns
// E_PERM if the bit is clear.
//
// Differential: parent spawns a child with empty ProcessRights (no
// vm_create bit), child invokes vm_create and replies with the syscall
// return value. Parent inspects the reply word.
//   Pre-patch: child's vm_create returns >= 0 (handle) or some non-perm
//     error (E_NODEV under TCG).
//   Post-patch: child's vm_create returns E_PERM (-2).
//
// Because we run under TCG (no -enable-kvm/no nested VMX guarantee), the
// pre-patch path may legitimately return E_NODEV instead of a positive
// handle. That still proves vulnerability vs. patched: the patched kernel
// rejects the call with E_PERM *before* hardware support is checked, so
// E_NODEV implies the vm_create gate did not run, i.e. VULNERABLE.

const lib = @import("lib");
const syscall = lib.syscall;
const perms = lib.perms;

const child_elf align(8) = @embedFile("zig-out/bin/child").*;

pub fn main(_: u64) void {
    const child_rights = (perms.ProcessRights{}).bits(); // empty: no vm_create
    const cr = syscall.proc_create(@intFromPtr(&child_elf), child_elf.len, child_rights);
    if (cr < 0) {
        syscall.write("POC-35bf077: proc_create failed\n");
        syscall.shutdown();
    }

    // Let the child reach ipc_recv.
    syscall.thread_yield();
    syscall.thread_yield();

    var reply: syscall.IpcMessage = .{};
    const rc = syscall.ipc_call(@intCast(cr), &.{}, &reply);
    if (rc < 0) {
        syscall.write("POC-35bf077: ipc_call failed\n");
        syscall.shutdown();
    }

    const child_vm_create_rc: i64 = @bitCast(reply.words[0]);
    if (child_vm_create_rc == syscall.E_PERM) {
        syscall.write("POC-35bf077: PATCHED (vm_create -> E_PERM)\n");
    } else {
        syscall.write("POC-35bf077: VULNERABLE (vm_create gate bypassed)\n");
    }
    syscall.shutdown();
}

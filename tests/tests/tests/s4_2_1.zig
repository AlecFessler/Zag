/// §4.2.1 — All VM syscalls with an invalid handle return `E_BADHANDLE`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var buf: [4096]u8 align(8) = .{0} ** 4096;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.1");
    // Process has no VM. Use a bogus handle. All VM handle syscalls should return E_BADCAP.
    var all_pass = true;
    const bad_handle: u64 = 0xDEAD;

    const r1 = syscall.vm_destroy();
    if (r1 != syscall.E_INVAL) {
        t.failWithVal("§4.2.1 vm_destroy", syscall.E_INVAL, r1);
        all_pass = false;
    }

    const r2 = syscall.vm_guest_map(bad_handle, 0, 0x1000, 0x1000, 0x1);
    if (r2 != syscall.E_BADHANDLE) {
        t.failWithVal("§4.2.1 vm_guest_map", syscall.E_BADHANDLE, r2);
        all_pass = false;
    }

    const r3 = syscall.vm_recv(bad_handle, @intFromPtr(&buf), 0);
    if (r3 != syscall.E_BADHANDLE) {
        t.failWithVal("§4.2.1 vm_recv", syscall.E_BADHANDLE, r3);
        all_pass = false;
    }

    const r4 = syscall.vm_reply_action(bad_handle, 0, 0);
    if (r4 != syscall.E_BADHANDLE) {
        t.failWithVal("§4.2.1 vm_reply", syscall.E_BADHANDLE, r4);
        all_pass = false;
    }

    const r5 = syscall.vm_vcpu_set_state(0xDEAD, 0);
    if (r5 != syscall.E_INVAL) {
        t.failWithVal("§4.2.1 vm_vcpu_set_state", syscall.E_INVAL, r5);
        all_pass = false;
    }

    const r6 = syscall.vm_vcpu_get_state(0xDEAD, 0);
    if (r6 != syscall.E_INVAL) {
        t.failWithVal("§4.2.1 vm_vcpu_get_state", syscall.E_INVAL, r6);
        all_pass = false;
    }

    const r7 = syscall.vm_vcpu_run(0xDEAD);
    if (r7 != syscall.E_INVAL) {
        t.failWithVal("§4.2.1 vm_vcpu_run", syscall.E_INVAL, r7);
        all_pass = false;
    }

    const r8 = syscall.vm_vcpu_interrupt(0xDEAD, 0);
    if (r8 != syscall.E_INVAL) {
        t.failWithVal("§4.2.1 vm_vcpu_interrupt", syscall.E_INVAL, r8);
        all_pass = false;
    }

    if (all_pass) {
        t.pass("§4.2.1");
    }
    syscall.shutdown();
}

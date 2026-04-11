/// §2.13.1 — All VM syscalls (except `vm_create`) return `E_INVAL` if the calling process has no VM.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

var buf: [4096]u8 align(8) = .{0} ** 4096;

pub fn main(_: u64) void {
    // Process has no VM. All VM syscalls except vm_create should return E_INVAL.
    var all_pass = true;

    const r1 = syscall.vm_destroy();
    if (r1 != syscall.E_INVAL) {
        t.failWithVal("§2.13.1 vm_destroy", syscall.E_INVAL, r1);
        all_pass = false;
    }

    const r2 = syscall.vm_guest_map(0, 0x1000, 0x1000, 0x1);
    if (r2 != syscall.E_INVAL) {
        t.failWithVal("§2.13.1 vm_guest_map", syscall.E_INVAL, r2);
        all_pass = false;
    }

    const r3 = syscall.vm_recv(@intFromPtr(&buf), 0);
    if (r3 != syscall.E_INVAL) {
        t.failWithVal("§2.13.1 vm_recv", syscall.E_INVAL, r3);
        all_pass = false;
    }

    const r4 = syscall.vm_reply_action(0, 0);
    if (r4 != syscall.E_INVAL) {
        t.failWithVal("§2.13.1 vm_reply", syscall.E_INVAL, r4);
        all_pass = false;
    }

    const r5 = syscall.vm_vcpu_set_state(0xDEAD, 0);
    if (r5 != syscall.E_INVAL) {
        t.failWithVal("§2.13.1 vm_vcpu_set_state", syscall.E_INVAL, r5);
        all_pass = false;
    }

    const r6 = syscall.vm_vcpu_get_state(0xDEAD, 0);
    if (r6 != syscall.E_INVAL) {
        t.failWithVal("§2.13.1 vm_vcpu_get_state", syscall.E_INVAL, r6);
        all_pass = false;
    }

    const r7 = syscall.vm_vcpu_run(0xDEAD);
    if (r7 != syscall.E_INVAL) {
        t.failWithVal("§2.13.1 vm_vcpu_run", syscall.E_INVAL, r7);
        all_pass = false;
    }

    const r8 = syscall.vm_vcpu_interrupt(0xDEAD, 0);
    if (r8 != syscall.E_INVAL) {
        t.failWithVal("§2.13.1 vm_vcpu_interrupt", syscall.E_INVAL, r8);
        all_pass = false;
    }

    if (all_pass) {
        t.pass("§2.13.1");
    }
    syscall.shutdown();
}

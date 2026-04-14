// PoC for fb41cbe: vm_vcpu_interrupt vector validation.
//
// Pre-patch: sysVmVcpuInterrupt and the vm_reply inject_interrupt path
// forward interrupt.vector to arch.vmInjectInterrupt without checking
// that vector >= 32. Intel SDM Vol 3A §6.3.1 reserves 0-31 for
// architectural exceptions. A VMM can inject (say) vector=5 and have
// the kernel write it directly into the VMCS VM-entry interruption-
// information field, bypassing LAPIC vector sanitization and
// corrupting guest exception handling.
//
// Post-patch: both entry points reject vector < 32 with E_INVAL.
//
// Differential: pre-patch returns E_OK (or otherwise non-E_INVAL) for
// vector=5, post-patch returns E_INVAL.

const lib = @import("lib");
const syscall = lib.syscall;
const perm_view = lib.perm_view;

var policy: [4096]u8 align(4096) = .{0} ** 4096;
var interrupt: [64]u8 align(8) = .{0} ** 64;

fn findVcpuHandle(view: [*]const perm_view.UserViewEntry, skip_handle: u64) u64 {
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_THREAD and view[i].handle != skip_handle) {
            return view[i].handle;
        }
    }
    return 0;
}

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    const self_handle: u64 = @bitCast(syscall.thread_self());

    const cr = syscall.vm_create(1, @intFromPtr(&policy));
    if (cr == syscall.E_NODEV) {
        syscall.write("POC-fb41cbe: SKIPPED (no VMX)\n");
        syscall.shutdown();
    }
    if (cr < 0) {
        syscall.write("POC-fb41cbe: UNEXPECTED vm_create failure\n");
        syscall.shutdown();
    }

    const vcpu_handle = findVcpuHandle(view, self_handle);
    if (vcpu_handle == 0) {
        syscall.write("POC-fb41cbe: UNEXPECTED no vcpu handle\n");
        syscall.shutdown();
    }

    interrupt[0] = 5; // vector — architectural exception, must be rejected
    interrupt[1] = 0; // external type
    interrupt[2] = 0; // no error code

    const ret = syscall.vm_vcpu_interrupt(vcpu_handle, @intFromPtr(&interrupt));
    if (ret == syscall.E_INVAL) {
        syscall.write("POC-fb41cbe: PATCHED (vector=5 -> E_INVAL)\n");
    } else {
        syscall.write("POC-fb41cbe: VULNERABLE (vector=5 accepted into VMCS)\n");
    }
    syscall.shutdown();
}

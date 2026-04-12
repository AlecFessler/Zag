/// §4.2.57 — `vm_msr_passthrough` with an invalid VM handle returns `E_BADCAP`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const MSR_IA32_TSC: u64 = 0x10;

pub fn main(_: u64) void {
    // No vm_create — pass a bogus handle.
    const result = syscall.vm_msr_passthrough(0xDEAD, MSR_IA32_TSC, 1, 1);
    t.expectEqual("§4.2.57", syscall.E_BADHANDLE, result);
    syscall.shutdown();
}

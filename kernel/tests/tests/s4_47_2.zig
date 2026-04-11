/// §4.47.2 — `vm_msr_passthrough` with no VM returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

const MSR_IA32_TSC: u64 = 0x10;

pub fn main(_: u64) void {
    // No vm_create — calling process has no VM.
    const result = syscall.vm_msr_passthrough(MSR_IA32_TSC, 1, 1);
    t.expectEqual("§4.47.2", syscall.E_INVAL, result);
    syscall.shutdown();
}

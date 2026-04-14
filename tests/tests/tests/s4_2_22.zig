/// §4.2.22 — `vm_destroy` syscall always returns `E_INVAL` (deprecated, use revoke_perm).
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    t.skipNoAarch64Vm("§4.2.22");
    // vm_destroy is deprecated — always returns E_INVAL.
    const result = syscall.vm_destroy();
    t.expectEqual("§4.2.22", syscall.E_INVAL, result);
    syscall.shutdown();
}

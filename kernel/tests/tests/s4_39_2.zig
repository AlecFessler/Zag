/// §4.39.2 — `vm_destroy` with no VM returns `E_INVAL`.
const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

pub fn main(_: u64) void {
    const result = syscall.vm_destroy();
    t.expectEqual("§4.39.2", syscall.E_INVAL, result);
    syscall.shutdown();
}

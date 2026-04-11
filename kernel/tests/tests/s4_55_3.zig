const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.55.3 — `sys_info` with `info_ptr` not pointing to a writable region of `sizeof(SysInfo)` bytes returns `E_BADADDR`.
///
/// Null pointer is never writable. We also pass `cores_ptr = 0` so the
/// kernel has no reason to reject the call for any other reason — the
/// *only* failure mode we want to observe here is `E_BADADDR` due to the
/// bad `info_ptr`.
pub fn main(_: u64) void {
    const rc = syscall.sys_info(0, 0);
    t.expectEqual("§4.55.3", syscall.E_BADADDR, rc);
    syscall.shutdown();
}

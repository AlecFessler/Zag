const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.3.9 — `sys_info` with `info_ptr` not pointing to a writable region of `sizeof(SysInfo)` bytes returns `E_BADADDR`.
///
/// We exercise two distinct rejection paths in `validateUserWritable`:
///
/// 1. **Null pointer.** Address 0 is unmapped and unwritable; the
///    handler must reject it before doing anything else. `cores_ptr` is
///    also 0 so the only failure surface is the bad `info_ptr`.
/// 2. **Kernel-partition pointer.** A canonical-form address inside the
///    higher-half kernel partition (`0xFFFF_8000_0000_0000`) lies outside
///    the user partition the validator is supposed to enforce. A correct
///    kernel must reject it with `E_BADADDR` even though the address is
///    a "valid" virtual address in some sense — this catches a regression
///    where the validator only checked for mapping presence and forgot
///    the partition-containment rule.
///
/// Both subtests live in the same file so the §5.3.9 spec tag still
/// binds to exactly one test.
pub fn main(_: u64) void {
    // (1) Null info_ptr.
    const rc_null = syscall.sys_info(0, 0);
    if (rc_null != syscall.E_BADADDR) {
        t.failWithVal("§5.3.9 null info_ptr", syscall.E_BADADDR, rc_null);
        syscall.shutdown();
    }

    // (2) Kernel-partition info_ptr. The base of the higher-half kernel
    // window is the canonical "should never be writable from userspace"
    // address.
    const kernel_addr: u64 = 0xFFFF_8000_0000_0000;
    const rc_kern = syscall.sys_info(kernel_addr, 0);
    if (rc_kern != syscall.E_BADADDR) {
        t.failWithVal("§5.3.9 kernel-partition info_ptr", syscall.E_BADADDR, rc_kern);
        syscall.shutdown();
    }

    t.pass("§5.3.9");
    syscall.shutdown();
}

const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §5.3.11 — `sys_info` with `cores_ptr` non-null must point to a writable region of `core_count * sizeof(CoreInfo)` bytes, where `core_count` is the value written to `info_ptr.core_count` by the same call; otherwise returns `E_BADADDR`.
///
/// Pass a valid `info_ptr` but a definitively non-writable `cores_ptr`
/// (address `1`: non-null, unaligned, and guaranteed unmapped — this
/// slips past the kernel's purely-symbolic `validateUserWritable`
/// range check and only fails at the page-walking `probeUserWritable`
/// helper, which is the exact path that satisfies §5.3.11 together
/// with the "no partial write to `info_ptr` on E_BADADDR" invariant).
/// §5.3.11 requires `E_BADADDR`.
pub fn main(_: u64) void {
    var info: syscall.SysInfo = undefined;
    // info_ptr intentionally valid. We use a sentinel so we can also
    // confirm the kernel did NOT leave a partial write in `info_ptr` on
    // the E_BADADDR path (the handler should validate cores_ptr before
    // committing either write, per the systems.md handler flow).
    const sentinel: u64 = 0xbeef_cafe_beef_cafe;
    info = .{ .core_count = sentinel, .mem_total = sentinel, .mem_free = sentinel };

    // A non-null but definitely unwritable cores_ptr: use address 1 so it
    // is both non-null and guaranteed unaligned / unmapped.
    const rc = syscall.sys_info(@intFromPtr(&info), 1);
    if (rc != syscall.E_BADADDR) {
        t.failWithVal("§5.3.11", syscall.E_BADADDR, rc);
        syscall.shutdown();
    }

    // Confirm no partial write to info_ptr on the failure path. The
    // handler is required to validate cores_ptr before committing any
    // write to info_ptr — if it didn't, core_count (and the other two
    // fields) would have been overwritten with the kernel's actual
    // values, which would never equal our sentinel.
    if (info.core_count != sentinel or info.mem_total != sentinel or info.mem_free != sentinel) {
        t.fail("§5.3.11 info_ptr was partially written on E_BADADDR path");
        syscall.shutdown();
    }

    t.pass("§5.3.11");
    syscall.shutdown();
}

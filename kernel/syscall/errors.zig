// Per spec §[error_codes], errors return a small positive integer in
// vreg 1 (1..15), with 0 = success. The kernel surfaces these directly
// via the syscall return path (`syscallDispatch` writes the i64 return
// value into rax / vreg 1). Internal helpers that distinguish success
// from failure must use `!= 0`, never `< 0`.

pub const E_ABANDONED: i64 = 1;
pub const E_BADADDR: i64 = 2;
pub const E_BADCAP: i64 = 3;
pub const E_BUSY: i64 = 4;
pub const E_CLOSED: i64 = 5;
pub const E_FULL: i64 = 6;
pub const E_INVAL: i64 = 7;
pub const E_NODEV: i64 = 8;
pub const E_NOENT: i64 = 9;
pub const E_NOMEM: i64 = 10;
pub const E_NOSPC: i64 = 11;
pub const E_PERM: i64 = 12;
pub const E_REFUSED: i64 = 13;
pub const E_TERM: i64 = 14;
pub const E_TIMEOUT: i64 = 15;

// E_AGAIN is not part of the spec error-code table (1..15). It's an
// internal-only sentinel for "no event ready, caller should suspend"
// used by `recv` and similar paths. Keep it negative so it can never
// collide with a valid spec error code surfaced through a vreg-1
// return; callers must consume it before returning to userspace.
pub const E_AGAIN: i64 = -1;

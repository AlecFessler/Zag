// Spec §[error_codes]: error codes are returned in vreg 1 by syscalls
// that fail, with values 1..15. Zero indicates success. Positive small
// integers (1..15) are reserved for these errors and never collide with
// successful return values: handle returns are spec-required to carry
// a non-zero type tag in bits 12..15 (id, type, _reserved, caps), so
// the smallest valid handle word is 1 << 12 = 4096; integer-only
// returns (counts, byte sizes, monotonic time) are likewise either
// >= 16 by construction or returned alongside a separate vreg 0 OK
// indicator. Userspace discriminates via `0 < v <= 15`.
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
pub const E_AGAIN: i64 = 16; // kernel-internal sentinel, not a spec code

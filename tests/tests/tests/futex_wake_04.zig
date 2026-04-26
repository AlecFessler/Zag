// Spec §[futex_wake] — test 04.
//
// "[test 04] on success, [1] is the number of ECs actually woken
//  (0..count)."
//
// Strategy
//   The full success post-condition asserts that `[1]` reports the
//   exact number of ECs woken from `futex_wait_val` / `futex_wait_change`
//   on the given address, capped by the `count` argument. Exercising
//   the non-zero branch requires another EC parked in `futex_wait_*`
//   on the same address. The test runner spawns each test as a single
//   capability domain whose initial EC executes `main`; the runner
//   does not currently provide a way for that EC to spawn a sibling
//   that parks in `futex_wait` and then have `main` call `futex_wake`
//   on the parked address (the sibling's wait is racy without a
//   secondary handshake the runner does not yet wire up).
//
//   SMOKE-DEGRADE: assert the lower bound of the spec range — that
//   `futex_wake` on a valid 8-byte-aligned user address with no ECs
//   currently parked on it returns success with `[1] = 0`. This is
//   the `0..count` lower endpoint and is sufficient to catch a kernel
//   that returns nonzero or returns an error word on a no-op wake.
//   The non-zero path will be covered once the runner gains
//   multi-EC-spawn primitives or this test is rewritten to use the
//   `bind_event_route` / `recv` machinery to synchronize a parked
//   sibling.
//
//   Choice of address: `cap_table_base` is the read-only handle-table
//   mapping (§[capabilities]: "the handle table is mapped read-only
//   into the holding domain"), which is a valid user address in the
//   caller's domain and is page-aligned (well above 8-byte aligned).
//   No EC is parked on it, so the kernel must report 0 woken.
//
// Action
//   1. futex_wake(addr=cap_table_base, count=1)
//      — must return OK with [1] = 0.
//
// Assertions
//   1: futex_wake returned non-OK (vreg 1 was an error code rather
//      than the woken count).
//   2: futex_wake returned a nonzero woken count even though no EC
//      was parked on the address.

const lib = @import("lib");

const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    // §[futex_wake] [1] addr: 8-byte-aligned user address in the
    // caller's domain. The handle-table base is page-aligned and
    // mapped into the caller's domain, so it satisfies both.
    const addr: u64 = cap_table_base;
    const count: u64 = 1;

    const result = syscall.futexWake(addr, count);

    // The kernel signals errors by placing an E_* code in vreg 1 (1..15
    // per §[error_codes]). A successful wake places the woken count in
    // vreg 1; for our no-parked-EC scenario that count must be 0.
    if (errors.isError(result.v1)) {
        testing.fail(1);
        return;
    }

    if (result.v1 != 0) {
        testing.fail(2);
        return;
    }

    testing.pass();
}

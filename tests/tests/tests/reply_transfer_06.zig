// Spec §[reply_transfer] — test 06.
//
// "[test 06] returns E_PERM if any pair entry's caps are not a subset
//  of the source handle's current caps."
//
// Strategy
//   The assertion needs:
//     (a) A reply handle in the caller's table with the `xfer` cap set
//         (so test 02 doesn't fire first).
//     (b) A pair entry that survives test 04 (no reserved bits) and
//         test 05 (valid source id), and whose `move`/`copy` choice is
//         consistent with the source handle's caps so that tests 07/08
//         don't fire first, but whose `caps` field has at least one
//         bit set that the source handle does *not* carry — which is
//         exactly the test 06 trip wire.
//
//   Producing (a) follows the same pipeline used by terminate_07: mint
//   a port with `xfer | recv | bind` (so the kernel issues a reply
//   handle with `xfer = 1` per §[reply] handle ABI), mint a worker EC
//   `W` with `susp | term`, `suspend(W, port)` to queue W as a
//   suspended sender, then `recv(port)` to dequeue it. The recv
//   syscall word carries `reply_handle_id` in bits 32-43 per §[recv].
//   `term` on W is included so the test ELF has a clean exit path
//   (terminate at the end) but is not required for the assertion.
//
//   Producing (b): reuse W as the source handle. W's caps are
//   {susp = 1, term = 1, copy = 1, restart_policy = 0} — `copy` lets
//   the kernel satisfy reply_transfer test 08 (move = 0 needs `copy`
//   on the source); `term`/`susp` give the source a non-empty cap set
//   to compare a subset against. The pair entry is encoded with
//   `move = 0` and `caps = {copy = 1, term = 1, susp = 1, write = 1}`
//   — `write` (bit 7) is *not* set on W, so the entry's caps are not
//   a subset of W's current caps. The earlier gates clear:
//     - test 01 (E_BADCAP):    [1] is the reply handle from recv
//     - test 02 (E_PERM xfer): port had `xfer`, so the reply has it
//     - test 03 (E_INVAL N):   N = 1 is in [1, 63]
//     - test 04 (E_INVAL res): reserved bits in [1] and the entry are 0
//     - test 05 (E_BADCAP id): entry.id = w_handle, valid in caller
//     - test 07 (E_PERM move): entry.move = 0, so the move-cap rule
//                              does not apply
//     - test 08 (E_PERM copy): source W has `copy = 1`, so the move=0
//                              copy-cap rule is satisfied
//     - test 09 (E_INVAL dup): only one entry, no duplicates possible
//
//   That leaves test 06 as the first remaining gate, so the kernel
//   must surface E_PERM (or fall through into a non-error success
//   path on a buggy implementation, in which case this test fails).
//
//   `reply_transfer` with N > 0 is not yet wired in libz (the wrapper
//   panics — the high-vreg push would need a 912-byte stack pad). We
//   open-code the syscall here: vreg 127 must land at `[rsp + 912]`
//   when the kernel reads it (= (127 - 13) * 8 above the syscall
//   word at `[rsp]`). Allocating 920 bytes of scratch covers the
//   word at offset 0 plus vreg 127 at offset 912; intermediate vregs
//   the kernel will not read are left undefined.
//
// Action
//   1. createPort(caps = {xfer, recv, bind}) — must succeed; xfer is
//      what propagates to the reply handle so test 02 doesn't fire
//      ahead of test 06.
//   2. createExecutionContext(target = self, caps = {susp, term,
//      copy, restart_policy = 0}) — must succeed; W's `copy` bit
//      keeps reply_transfer test 08 happy when the entry has move = 0.
//   3. suspend(W, port) — must return OK; queues W as a suspended
//      sender on the port.
//   4. recv(port) — must return OK; the syscall word carries
//      reply_handle_id in bits 32-43.
//   5. reply_transfer(reply, [{ id = w_handle, move = 0,
//      caps = {copy, term, susp, write} }]) — must return E_PERM
//      (the spec assertion under test). Issued via inline asm because
//      libz's replyTransfer panics on N > 0.
//   6. terminate(W) — best-effort cleanup (W still in suspended/
//      reply-pending state if the kernel didn't consume the reply on
//      the failing path, but the test outcome has already been
//      reported by then — terminate is purely hygiene).
//
// Assertions
//   1: createPort failed (precondition for the assertion under test).
//   2: createExecutionContext failed (precondition).
//   3: suspend(W, port) did not return OK (precondition).
//   4: recv(port) did not return OK (precondition).
//   5: reply_transfer returned something other than E_PERM (the spec
//      assertion under test).

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // Step 1: mint the port. xfer is what gets propagated into the
    // minted reply handle's caps per §[reply] ("xfer = 1 if and only
    // if the recv'ing port had the xfer cap"). recv lets us dequeue
    // the suspension; bind lets W's `suspend` reach this port.
    const port_caps = caps.PortCap{
        .xfer = true,
        .recv = true,
        .bind = true,
    };
    const cp = syscall.createPort(@as(u64, port_caps.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Step 2: mint W. susp lets the test queue W on the port via
    // suspend. copy keeps reply_transfer test 08 (move = 0 needs the
    // copy cap on the source) satisfied so test 06 fires first. term
    // lets the test tear W down at the end. restart_policy = 0 stays
    // inside ec_inner_ceiling.
    const w_caps = caps.EcCap{
        .susp = true,
        .term = true,
        .copy = true,
        .restart_policy = 0,
    };
    const ec_caps_word: u64 = @as(u64, w_caps.toU16());
    const entry: u64 = @intFromPtr(&testing.dummyEntry);
    const cec = syscall.createExecutionContext(
        ec_caps_word,
        entry,
        1,
        0,
        0,
    );
    if (testing.isHandleError(cec.v1)) {
        testing.fail(2);
        return;
    }
    const w_handle: u12 = @truncate(cec.v1 & 0xFFF);

    // Step 3: queue W as a suspended sender on the port. Per
    // §[suspend], when [1] != self the call simply queues the target
    // and returns OK without blocking the caller.
    const sus = syscall.issueReg(.@"suspend", 0, .{
        .v1 = w_handle,
        .v2 = port_handle,
    });
    if (sus.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(3);
        return;
    }

    // Step 4: dequeue W. The recv syscall word's reply_handle_id is
    // at bits 32-43 per §[recv].
    const got = syscall.recv(port_handle, 0);
    if (got.regs.v1 != @intFromEnum(errors.Error.OK)) {
        testing.fail(4);
        return;
    }
    const reply_handle_id: u12 = @truncate((got.word >> 32) & 0xFFF);

    // Step 5: build a pair entry whose caps are NOT a subset of W's
    // current caps. W has {susp, term, copy}; entry adds `write`
    // (EcCap bit 7) which W lacks. move = 0, so the source's `copy`
    // bit (which W has) clears reply_transfer test 08 ahead of test
    // 06.
    const entry_caps = caps.EcCap{
        .copy = true,
        .term = true,
        .susp = true,
        .write = true, // <-- NOT a subset bit
    };
    const pair = caps.PairEntry{
        .id = w_handle,
        .caps = entry_caps.toU16(),
        .move = false,
    };
    const pair_u64: u64 = pair.toU64();

    // syscall_num = 39 (reply_transfer); N = 1 in bits 12-19;
    // reply_handle_id in bits 20-31. Per §[reply_transfer] (new ABI)
    // the reply handle id rides in the syscall word; the sole pair
    // entry rides in vreg 127. Vreg 127 lives at [rsp + (127-13)*8] =
    // [rsp + 912] when the kernel reads the stack frame, so we reserve
    // 920 bytes (word at offset 0, entry at offset 912), syscall, then
    // unwind. libz's replyTransfer panics on N > 0; the open-coded
    // path here is the documented workaround.
    const word: u64 = 39 |
        (@as(u64, 1) << 12) |
        ((@as(u64, reply_handle_id) & 0xFFF) << 20);
    var rax: u64 = undefined;
    asm volatile (
        \\ subq $920, %%rsp
        \\ movq %%rcx, (%%rsp)
        \\ movq %[entry], 912(%%rsp)
        \\ syscall
        \\ addq $920, %%rsp
        : [rax] "={rax}" (rax),
        : [word] "{rcx}" (word),
          [entry] "{rdi}" (pair_u64),
        : .{ .rcx = true, .r11 = true, .memory = true });

    if (rax != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(5);
        return;
    }

    // Hygiene: tear W down. Spec test 11 says on the E_FULL path the
    // reply handle is NOT consumed; the spec doesn't pin consumption
    // for the test 06 path explicitly, but consumption isn't required
    // for the assertion. We don't probe the reply handle further —
    // the assertion under test has already fired.
    _ = syscall.terminate(w_handle);

    testing.pass();
}

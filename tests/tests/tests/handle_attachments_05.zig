// Spec §[handle_attachments] handle_attachments — test 05.
//
// "[test 05] returns E_PERM if any entry with `move = 0` references a
//  source handle that lacks the `copy` cap."
//
// Strategy
//   The runner mints the result port with caps `{xfer, bind}` only —
//   no `move`, no `copy` — and passes it to each test domain at slot
//   `SLOT_FIRST_PASSED` (= 3). That single handle is exactly what test
//   05 needs as the source of an attachment with `move = 0`: it is a
//   live, valid handle in this domain whose caps deliberately lack
//   `copy`.
//
//   We also use the same slot-3 port as the suspend port [2]. It has
//   `xfer` (so test 01 cannot fire) and `bind` (so the suspend syscall's
//   own §[suspend] test 04 — port lacks bind — cannot fire). Neither
//   `move` nor `copy` is required on the suspending port itself; only
//   on the source handle of an attachment.
//
//   We use the initial EC at slot 1 as [1] (target = self). The runner
//   grants the test domain's `ec_inner_ceiling` 0xFF, so slot 1 carries
//   `susp` along with all other EC caps, neutralizing §[suspend] test 03
//   (lacks `susp`).
//
//   With every other §[handle_attachments] gate cleared, only test 05
//   can resolve the suspend with E_PERM:
//     - test 01 (port lacks xfer): slot-3 has xfer.            cleared
//     - test 02 (BADCAP for invalid source): slot-3 is valid.  cleared
//     - test 03 (entry caps ⊄ source caps): entry caps = 0,
//       trivially a subset.                                    cleared
//     - test 04 (move=1 with no move cap): we use move=0;
//       test 04 only applies to move=1 entries.                cleared
//     - test 06 (reserved bits set): the entry's _reserved_lo,
//       _reserved_hi, and the syscall word's reserved windows
//       are all zero.                                          cleared
//     - test 07 (duplicate sources): N=1.                      cleared
//   Slot-3 has no `copy` cap → test 05 must fire → E_PERM.
//
//   The §[handle_attachments] entry layout places pair entries in vregs
//   `[128-N..127]`. With N=1 the entry sits at vreg 127. Per the v3
//   syscall ABI (libz/syscall.zig), vreg N for N >= 14 lives at
//   `[rsp + (N-13)*8]` at syscall time, so vreg 127 is at `[rsp + 912]`
//   with the syscall word at `[rsp + 0]`. The libz `suspendEc` wrapper
//   panics on N>0 (its high-vreg path is unwired), so we issue the
//   syscall directly via inline asm: allocate a 920-byte stack pad, write
//   the entry at offset 912, write the syscall word at offset 0, load
//   register-backed vregs 1 and 2, then `syscall`.
//
// Action
//   1. Build pair entry { id = SLOT_FIRST_PASSED, caps = 0, move = 0 }.
//   2. Build syscall word with num = .suspend and pair_count = 1.
//   3. subq $920,%rsp; movq entry,912(%rsp); movq word,(%rsp); syscall.
//   4. Read returned vreg 1 (rax) — must equal E_PERM.
//
// Assertions
//   1: suspend with the move=0 / no-copy entry returned something other
//      than E_PERM.

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    // §[handle_attachments] entry encoding: id in bits 0-11, caps in
    // bits 16-31, move in bit 32; reserved bands all zero. caps = 0 is
    // a trivial subset of the source's {xfer, bind}, so test 03 is
    // neutralized; move = 0 is precisely what test 05 targets.
    const entry = caps.PairEntry{
        .id = caps.SLOT_FIRST_PASSED,
        .caps = 0,
        .move = false,
    };
    const entry_word: u64 = entry.toU64();

    // Syscall word: num = .suspend (id 34) in bits 0-11, pair_count = 1
    // in bits 12-19, all other bits zero.
    const word: u64 = syscall.buildWord(.@"suspend", syscall.extraCount(1));

    const ec_handle: u64 = caps.SLOT_INITIAL_EC;
    const port_handle: u64 = caps.SLOT_FIRST_PASSED;

    // High-vreg attachment path. Pad the stack with 920 bytes (115
    // qwords) so vreg 127 lands at [rsp + 912] and vreg 0 (the syscall
    // word) lands at [rsp + 0] when the kernel reads them. Inputs:
    //   rax = vreg 1  ([1] = target EC)
    //   rbx = vreg 2  ([2] = port)
    //   rcx = syscall word (clobbered by `syscall` to return RIP; we
    //         materialize it onto the stack at offset 0 first)
    //   r10 = scratch holding the entry word; we spill it to [rsp+912]
    //         before the syscall runs.
    var rax_out: u64 = undefined;
    asm volatile (
        \\ subq $920, %%rsp
        \\ movq %[entry], 912(%%rsp)
        \\ movq %%rcx, (%%rsp)
        \\ syscall
        \\ addq $920, %%rsp
        : [rax_out] "={rax}" (rax_out),
        : [word] "{rcx}" (word),
          [iv1] "{rax}" (ec_handle),
          [iv2] "{rbx}" (port_handle),
          [entry] "r" (entry_word),
        : .{ .rcx = true, .r11 = true, .rdx = true, .rbp = true, .rsi = true, .rdi = true, .r8 = true, .r9 = true, .r10 = true, .r12 = true, .r13 = true, .r14 = true, .r15 = true, .memory = true });

    if (rax_out != @intFromEnum(errors.Error.E_PERM)) {
        testing.fail(1);
        return;
    }

    testing.pass();
}

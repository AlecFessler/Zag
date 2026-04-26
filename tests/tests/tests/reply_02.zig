// Spec §[reply] reply — test 02.
//
// "[test 02] returns E_INVAL if any reserved bits are set in [1]."
//
// Strategy
//   The [1] reply-handle word carries the 12-bit handle id in bits
//   0-11 with bits 12-63 _reserved (§[capabilities]: "handle in the
//   caller's table (bits 0-11; upper bits _reserved)"). §[syscall_abi]
//   pins the reserved-bit check at the ABI layer: "Bits not assigned
//   by the invoked syscall must be zero on entry; the kernel returns
//   E_INVAL if a reserved bit is set."
//
//   Because the reserved-bit gate is ABI-layer it fires regardless of
//   whether the low 12 bits would otherwise resolve to a valid reply
//   handle. The same shape is used by sync_02 / delete_02 / ack_04:
//   any handle id in the low bits is acceptable so long as a reserved
//   bit is set somewhere above bit 11.
//
//   To keep the setup minimal we mint a fresh port handle and stuff
//   its slot id into bits 0-11 of [1] — the type/cap-validity check
//   for "is this a reply handle" is downstream of the reserved-bit
//   check, so even though a port handle is not a reply handle the
//   E_INVAL must surface first.
//
//   The libz `syscall.reply` wrapper takes `reply_handle: u12`, which
//   cannot carry reserved bits. We bypass that wrapper and dispatch
//   through `syscall.issueReg` directly so we can stuff bit 63 into
//   vreg 1. Bit 63 mirrors the reference pattern in ack_04.zig — it
//   sits well above any plausible future field on a handle word.
//
// Action
//   1. create_port(caps={bind})              — must succeed
//   2. reply(handle | (1 << 63))             — must return E_INVAL
//      (reserved bit 63 of [1] set; low 12 bits hold a valid id)
//
// Assertions
//   1: setup syscall failed (create_port returned an error word)
//   2: reply with reserved bit 63 of [1] returned something other
//      than E_INVAL

const lib = @import("lib");

const caps = lib.caps;
const errors = lib.errors;
const syscall = lib.syscall;
const testing = lib.testing;

pub fn main(cap_table_base: u64) void {
    _ = cap_table_base;

    const initial = caps.PortCap{ .bind = true };
    const cp = syscall.createPort(@as(u64, initial.toU16()));
    if (testing.isHandleError(cp.v1)) {
        testing.fail(1);
        return;
    }
    const port_handle: u12 = @truncate(cp.v1 & 0xFFF);

    // Reserved bit 63 of [1] set; low 12 bits hold a valid id. Bypass
    // the typed wrapper since `syscall.reply` takes u12 and would
    // truncate the reserved bit before it reaches the kernel.
    const handle_with_reserved: u64 = @as(u64, port_handle) | (@as(u64, 1) << 63);
    const r = syscall.issueReg(.reply, 0, .{ .v1 = handle_with_reserved });
    if (r.v1 != @intFromEnum(errors.Error.E_INVAL)) {
        testing.fail(2);
        return;
    }

    testing.pass();
}

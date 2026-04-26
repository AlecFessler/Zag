const zag = @import("zag");

const capability = zag.caps.capability;
const errors = zag.syscall.errors;
const port = zag.sched.port;

const ExecutionContext = zag.sched.execution_context.ExecutionContext;
const HANDLE_ARG_MASK = capability.HANDLE_ARG_MASK;
const ReplyCaps = port.ReplyCaps;
const Word0 = capability.Word0;

/// Pair entry layout — Spec §[handle_attachments].
/// bits 0-11 source handle id, 16-31 caps, 32 move flag. All other bits
/// must be zero.
const PAIR_SOURCE_MASK: u64 = 0xFFF;
const PAIR_CAPS_MASK: u64 = @as(u64, 0xFFFF) << 16;
const PAIR_MOVE_BIT: u64 = @as(u64, 1) << 32;
const PAIR_VALID_MASK: u64 = PAIR_SOURCE_MASK | PAIR_CAPS_MASK | PAIR_MOVE_BIT;

const MIN_PAIR_COUNT: usize = 1;
const MAX_PAIR_COUNT: usize = 63;

/// Consumes a reply handle and resumes the suspended EC. State
/// modifications written to the receiver's event-state vregs (per
/// §[event_state] / §[vm_exit_state]) between recv and reply are applied
/// to the suspended EC's state on resume, gated by the `write` cap on the
/// EC handle that originated the binding (the suspending EC handle for
/// explicit suspend, the EC handle used at `bind_event_route` for fault
/// events, the vCPU EC handle for vm_exit).
///
/// ```
/// reply([1] reply) -> void
///   syscall_num = 38
///
///   [1] reply: reply handle
/// ```
///
/// No self-handle cap required — the reply handle itself authorizes the
/// operation.
///
/// [test 01] returns E_BADCAP if [1] is not a valid reply handle.
/// [test 02] returns E_INVAL if any reserved bits are set in [1].
/// [test 03] returns E_TERM if the suspended EC was terminated before reply could deliver; [1] is consumed.
/// [test 04] on success, [1] is consumed (removed from the caller's table).
/// [test 05] on success when the originating EC handle had the `write` cap, the resumed EC's state reflects modifications written to the receiver's event-state vregs between recv and reply.
/// [test 06] on success when the originating EC handle did not have the `write` cap, the resumed EC's state matches its pre-suspension state, ignoring any modifications made by the receiver.
/// [test 07] on success, the suspended EC is resumed.
pub fn reply(caller: *anyopaque, reply_handle: u64) i64 {
    if (reply_handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const slot: u12 = @truncate(reply_handle);

    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;
    const entry_present = capability.resolveHandleOnDomain(cd, slot, .reply) != null;
    cd_ref.unlock();
    if (!entry_present) return errors.E_BADCAP;

    return port.reply(ec, reply_handle);
}

/// Consumes a reply handle, resumes the suspended EC, and attaches N
/// handles to the resumption. The resumed EC's syscall word carries
/// `pair_count = N` and `tstart = S` (slot id of the first attached
/// handle in the resumed EC's domain). State writes are applied per
/// `reply` semantics.
///
/// ```
/// reply_transfer([1] reply, [128-N..127] pair_entries) -> void
///   syscall_num = 39
///
///   syscall word bits 12-19: N (1..63)
///
///   [1] reply: reply handle
///   [128-N..127]: pair entries packed per §[handle_attachments]
/// ```
///
/// Reply cap required on [1]: `xfer`.
///
/// [test 01] returns E_BADCAP if [1] is not a valid reply handle.
/// [test 02] returns E_PERM if [1] does not have the `xfer` cap.
/// [test 03] returns E_INVAL if N is 0 or N > 63.
/// [test 04] returns E_INVAL if any reserved bits are set in [1] or any pair entry.
/// [test 05] returns E_BADCAP if any pair entry's source handle id is not valid in the caller's domain.
/// [test 06] returns E_PERM if any pair entry's caps are not a subset of the source handle's current caps.
/// [test 07] returns E_PERM if any pair entry with `move = 1` references a source handle that lacks the `move` cap.
/// [test 08] returns E_PERM if any pair entry with `move = 0` references a source handle that lacks the `copy` cap.
/// [test 09] returns E_INVAL if two pair entries reference the same source handle.
/// [test 10] returns E_TERM if the suspended EC was terminated before reply could deliver; [1] is consumed and no handle transfer occurs.
/// [test 11] returns E_FULL if the resumed EC's domain handle table cannot accommodate N contiguous slots; [1] is NOT consumed and the caller's table is unchanged.
/// [test 12] on success, [1] is consumed; the resumed EC's syscall word `pair_count = N` and `tstart = S`; the next N slots [S, S+N) in the resumed EC's domain contain the inserted handles per §[handle_attachments] (caps intersected with `idc_rx` for IDC handles, verbatim otherwise).
/// [test 13] on success, source pair entries with `move = 1` are removed from the caller's table; entries with `move = 0` are not removed.
/// [test 14] on success when the originating EC handle had the `write` cap, the resumed EC's state reflects modifications written to the receiver's event-state vregs between recv and reply_transfer; otherwise modifications are discarded.
/// [test 15] on success, the suspended EC is resumed.
pub fn replyTransfer(caller: *anyopaque, reply_handle: u64, pair_entries: []const u64) i64 {
    if (reply_handle & ~HANDLE_ARG_MASK != 0) return errors.E_INVAL;
    if (pair_entries.len < MIN_PAIR_COUNT or pair_entries.len > MAX_PAIR_COUNT) return errors.E_INVAL;

    if (validatePairEntryBits(pair_entries)) |err| return err;
    if (hasDuplicateSources(pair_entries)) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const slot: u12 = @truncate(reply_handle);

    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;
    const reply_present = capability.resolveHandleOnDomain(cd, slot, .reply) != null;
    var has_xfer = false;
    if (reply_present) {
        const caps_word = Word0.caps(cd.user_table[slot].word0);
        const reply_caps: ReplyCaps = @bitCast(caps_word);
        has_xfer = reply_caps.xfer;
    }
    cd_ref.unlock();

    if (!reply_present) return errors.E_BADCAP;
    if (!has_xfer) return errors.E_PERM;

    const n: u8 = @intCast(pair_entries.len);
    return port.replyTransfer(ec, reply_handle, n);
}

/// Reserved-bit check for every pair entry — Spec §[handle_attachments]
/// test 06.
fn validatePairEntryBits(entries: []const u64) ?i64 {
    for (entries) |entry| {
        if (entry & ~PAIR_VALID_MASK != 0) return errors.E_INVAL;
    }
    return null;
}

/// Intra-batch source-id duplicate check — Spec §[handle_attachments]
/// test 07. O(N²) is fine: N ≤ 63 and the alternative (sort or bitmap)
/// would allocate.
fn hasDuplicateSources(entries: []const u64) bool {
    var i: usize = 0;
    while (i < entries.len) {
        const a: u12 = @truncate(entries[i] & PAIR_SOURCE_MASK);
        var j: usize = i + 1;
        while (j < entries.len) {
            const b: u12 = @truncate(entries[j] & PAIR_SOURCE_MASK);
            if (a == b) return true;
            j += 1;
        }
        i += 1;
    }
    return false;
}

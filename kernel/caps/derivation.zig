//! Capability derivation tree. See docs/kernel/specv3.md §[capabilities].
//!
//! Every used `KernelHandle` slot carries three cross-domain links —
//! `parent`, `first_child`, `next_sibling` — that together form the copy
//! ancestry tree the `revoke` syscall walks.
//!
//! Tree shape:
//!   - The handle minted by a `create_*` syscall is a tree root: its
//!     `parent` link is null in the used state.
//!   - The handle minted as a copy via `derive` (driven by the
//!     handle-attachment paths in suspend/recv/reply_transfer) is hung
//!     under the source as the new head of `source.first_child`. Older
//!     siblings shift down via `next_sibling`.
//!   - `revoke(target)` releases every transitive descendant of
//!     `target` (DFS over `first_child`/`next_sibling`); the target
//!     itself is NOT released — Spec test 05.
//!   - `delete(target)` reparents `target`'s children to `target.parent`
//!     before clearing `target`'s slot, so a later `revoke` on any
//!     ancestor still reaches the descendant subtree (Spec test 04 —
//!     a moved descendant is still on the chain).
//!
//! Cross-domain locking: the tree spans capability domains, so naive
//! per-domain locking risks AB-BA when two domains hold cross-derived
//! handles. We take a single global `tree_mutex` for the whole tree
//! mutation and walk all participating domains with that single lock
//! held — gen validation on each domain reference still catches
//! freed-domain races. TODO: scope this lock per-tree (e.g. partition
//! by root) once profiling shows contention.
//!
//! NOTE: We intentionally do not store `prev_sibling`. The in-kernel
//! `delete` of a single handle therefore costs O(siblings) — scan from
//! `parent.first_child` until finding the predecessor and patching its
//! `next_sibling`. We can add `prev_sibling` (4 pointers per handle, +8B)
//! for O(1) splice if profiling shows that fanout per source is large
//! enough to matter. Most use cases have small fanout (a server hands a
//! port to a handful of clients), so for now we accept the linear cost.

const std = @import("std");
const zag = @import("zag");

const capability = zag.caps.capability;
const capability_domain = zag.capdom.capability_domain;
const errors = zag.syscall.errors;

const CapabilityDomain = capability_domain.CapabilityDomain;
const CapabilityType = capability.CapabilityType;
const ErasedSlabRef = capability.ErasedSlabRef;
const HandleLink = capability.HandleLink;
const KernelHandle = capability.KernelHandle;
const SpinLock = zag.utils.sync.SpinLock;
const Word0 = capability.Word0;

/// Defensive bound on tree-walk depth. Caps both the max depth a single
/// tree can reach and the sibling-chain length we will scan before
/// asserting corruption. Per-domain handle count is 4096; that bounds
/// single-domain depth, but a tree spanning N domains can reach
/// `N * 4096`. A flat 1<<20 ceiling is generous in practice.
const MAX_DEPTH: u32 = 1 << 20;

/// Single global mutex serializing every tree mutation. See module-
/// level note. Acquired by `derive` and `revoke` for the full duration
/// of their work. Each per-domain access still goes through that
/// domain's `_gen_lock` for staleness validation; the tree mutex only
/// orders concurrent tree mutations against each other.
var tree_mutex: SpinLock = .{ .class = "caps.derivation.tree_mutex" };

// ── External API ─────────────────────────────────────────────────────

/// Release `handle`'s subtree in the copy-derivation tree.
/// Spec §[capabilities].revoke.
///
/// Walks every transitive descendant of the calling-domain handle DFS
/// over `first_child`/`next_sibling`, applies per-type release on each,
/// and clears its slot. Does NOT release `handle` itself (Spec test 05)
/// and does NOT touch any handle on the copy-ancestor side (Spec test
/// 06). After return, `handle.first_child` is null.
pub fn revoke(caller_domain: ErasedSlabRef, handle: u64) i64 {
    if (handle & ~capability.HANDLE_ARG_MASK != 0) return errors.E_INVAL;

    const slot: u12 = @truncate(handle);

    tree_mutex.lock(@src());
    defer tree_mutex.unlock();

    const cd = caller_domain.lockTyped(CapabilityDomain) catch
        return errors.E_BADCAP;
    defer caller_domain.unlockTyped(CapabilityDomain);

    const entry = capability.resolveHandleOnDomain(cd, slot, null) orelse
        return errors.E_BADCAP;
    assertInTree(entry);

    // Detach the entire `first_child` list and walk it. The target
    // itself remains in place, with `first_child` cleared.
    const head = entry.first_child;
    entry.first_child = .{};

    releaseSiblingChain(head, cd);
    return 0;
}

/// `delete` syscall driver. Spec §[capabilities].delete.
///
/// Takes `tree_mutex` then the caller's domain gen-lock (matching the
/// order in `derive`/`revoke`), detaches the handle from the
/// copy-derivation tree, runs the per-type release, and clears the
/// slot.
pub fn deleteAndDetach(caller_domain: ErasedSlabRef, slot: u12) i64 {
    tree_mutex.lock(@src());
    defer tree_mutex.unlock();

    const cd = caller_domain.lockTyped(CapabilityDomain) catch
        return errors.E_BADCAP;

    // SLOT_SELF special case. The slot's type tag is
    // `.capability_domain_self` — `capability.releaseHandle` routes to
    // `capability_domain.releaseSelf`, which calls
    // `destroyCapabilityDomain` -> `slab_instance.destroyLocked`. That
    // clears the lock bit and bumps gen → even (freed) atomically, then
    // frees the user/kernel table PMM blocks. After this, both the cd
    // struct (now on the slab freelist) and the user_table/kernel_table
    // memory are unsafe to touch:
    //   - `clearAndFreeSlot` writes to `holder.user_table[slot]` (freed
    //     PMM block) and `&holder.kernel_table[slot]` (freed PMM block).
    //   - The deferred `unlockTyped` would assert `prev & 1 == 1` on a
    //     gen-lock word whose lock bit was just cleared by
    //     `destroyLocked` — assertion failure on debug builds.
    // Bypass both for slot 0.
    if (slot == 0) {
        capability.releaseHandle(cd, slot, undefined);
        return 0;
    }
    defer caller_domain.unlockTyped(CapabilityDomain);

    const entry = capability.resolveHandleOnDomain(cd, slot, null) orelse
        return errors.E_BADCAP;

    detachForDelete(cd, slot, entry);
    capability.releaseHandle(cd, slot, entry);
    capability.clearAndFreeSlot(cd, slot, entry);
    return 0;
}

/// Detach `entry` from the copy-derivation tree. Reparents `entry`'s
/// children to its parent so `revoke` on an ancestor still reaches the
/// descendants — Spec §[capabilities].revoke test 04.
///
/// Caller has both `tree_mutex` and `entry_dom`'s gen-lock; this
/// function does NOT take either. Skips the gen-lock acquisition when
/// a traversed link names `entry_dom`.
fn detachForDelete(
    entry_dom: *CapabilityDomain,
    entry_slot: u12,
    entry: *KernelHandle,
) void {
    assertInTree(entry);

    const parent_link = entry.parent;
    const next_sibling = entry.next_sibling;
    const first_child = entry.first_child;

    // Reparent every child to entry.parent. Track the last child so
    // we can splice its next_sibling onto entry.next_sibling after.
    var cur = first_child;
    var last_child_link: ?HandleLink = null;
    var depth: u32 = 0;
    while (cur.domain.ptr != null) {
        std.debug.assert(depth < MAX_DEPTH);
        const c = lockEntrySkip(cur, entry_dom) orelse break;
        c.entry.parent = parent_link;
        last_child_link = cur;
        const nxt = c.entry.next_sibling;
        unlockEntrySkip(c, entry_dom);
        if (nxt.domain.ptr == null) break;
        cur = nxt;
        depth += 1;
    }

    if (last_child_link) |last_link| {
        if (lockEntrySkip(last_link, entry_dom)) |lc| {
            lc.entry.next_sibling = next_sibling;
            unlockEntrySkip(lc, entry_dom);
        }
    }

    const replacement: HandleLink = if (first_child.domain.ptr != null) first_child else next_sibling;

    if (parent_link.domain.ptr != null) {
        if (lockEntrySkip(parent_link, entry_dom)) |p| {
            replaceLinkInChildList(p.entry, entry_dom, entry_slot, replacement, entry_dom);
            unlockEntrySkip(p, entry_dom);
        }
    }
    // entry was a root (or parent dead): the children become roots
    // themselves. They've already had their parent links nulled
    // (via parent_link being .{}). There is nothing else to do.

    entry.parent = .{};
    entry.first_child = .{};
    entry.next_sibling = .{};
}

// ── Internal helpers ─────────────────────────────────────────────────

/// Pair of `(*CapabilityDomain, *KernelHandle)` returned by
/// `lockEntry` so callers can unlock symmetrically. `dom_ref` is the
/// erased ref the caller used to acquire the typed lock — kept so
/// `unlockEntrySkip` can release the same lock + apply the same
/// `held` skip rule. The actual `*CapabilityDomain` stays internal to
/// `lockEntrySkip`'s walk; callers reach the entry through `.entry`.
const LockedEntry = struct {
    dom_ref: ErasedSlabRef,
    entry: *KernelHandle,
};

/// Lock the holder domain of a tree link and return a pointer to the
/// referenced kernel-table entry. Returns null on stale domain or bad
/// link (out-of-range slot, free slot). Caller must call `unlockEntrySkip`.
///
/// `held` names a domain whose gen-lock the caller already holds; if
/// the link names `held`, the gen-lock acquisition is skipped (would
/// deadlock against the held lock).
fn lockEntrySkip(link: HandleLink, held: ?*CapabilityDomain) ?LockedEntry {
    if (link.domain.ptr == null) return null;

    const same_held = held != null and link.domain.ptr == @as(*anyopaque, @ptrCast(held.?));
    const dom: *CapabilityDomain = if (same_held)
        held.?
    else
        (link.domain.lockTyped(CapabilityDomain) catch return null);

    if (@as(u16, link.slot) >= capability.MAX_HANDLES_PER_DOMAIN) {
        if (!same_held) link.domain.unlockTyped(CapabilityDomain);
        return null;
    }
    const entry = &dom.kernel_table[@as(u12, @intCast(link.slot))];
    if (entry.ref.ptr == null) {
        if (!same_held) link.domain.unlockTyped(CapabilityDomain);
        return null;
    }
    return .{ .dom_ref = link.domain, .entry = entry };
}

fn unlockEntrySkip(le: LockedEntry, held: ?*CapabilityDomain) void {
    if (held != null and le.dom_ref.ptr == @as(*anyopaque, @ptrCast(held.?))) return;
    le.dom_ref.unlockTyped(CapabilityDomain);
}

/// Install `child_entry` as the new head of `parent_entry.first_child`.
/// Asserts same `CapabilityType`. Both domains must be locked by caller.
fn linkAsChild(
    parent_domain: ErasedSlabRef,
    parent_slot: u12,
    parent_entry: *KernelHandle,
    target_domain: ErasedSlabRef,
    child_slot: u12,
    child_entry: *KernelHandle,
    parent_type: CapabilityType,
    child_word0: u64,
) void {
    std.debug.assert(parent_type == Word0.typeTag(child_word0));
    std.debug.assert(parent_entry.ref.ptr != null);
    std.debug.assert(child_entry.ref.ptr != null);

    child_entry.parent = .{
        .domain = parent_domain,
        .slot = @as(u16, parent_slot),
    };
    child_entry.next_sibling = parent_entry.first_child;
    child_entry.first_child = .{};
    parent_entry.first_child = .{
        .domain = target_domain,
        .slot = @as(u16, child_slot),
    };
}

/// Walk a sibling chain rooted at `head`, releasing each subtree DFS.
/// `caller_dom` is the calling domain — kept locked throughout — and
/// is unlocked transiently if a descendant lives in the same domain
/// (so `lockTyped` does not deadlock against the same gen-lock).
fn releaseSiblingChain(initial_head: HandleLink, caller_dom: *CapabilityDomain) void {
    var head = initial_head;
    var depth: u32 = 0;
    while (head.domain.ptr != null) {
        std.debug.assert(depth < MAX_DEPTH);
        const next = popSibling(&head, caller_dom) orelse break;
        releaseSubtree(next, caller_dom);
        depth += 1;
    }
}

/// Pop the head of a sibling chain, returning the popped link. Updates
/// `head` to the next sibling. Returns null if the chain is empty or
/// the popped link is unreachable (stale domain).
///
/// Locks the popped entry's holder domain transiently (skipping when
/// it is the caller's own domain, which is already locked).
fn popSibling(head: *HandleLink, caller_dom: *CapabilityDomain) ?HandleLink {
    const popped = head.*;
    if (popped.domain.ptr == null) return null;

    const same_caller = popped.domain.ptr == @as(*anyopaque, @ptrCast(caller_dom));
    const dom: *CapabilityDomain = if (same_caller) caller_dom else (popped.domain.lockTyped(CapabilityDomain) catch {
        head.* = .{};
        return null;
    });
    defer if (!same_caller) popped.domain.unlockTyped(CapabilityDomain);

    if (@as(u16, popped.slot) >= capability.MAX_HANDLES_PER_DOMAIN) {
        head.* = .{};
        return null;
    }
    const entry = &dom.kernel_table[@as(u12, @intCast(popped.slot))];
    if (entry.ref.ptr == null) {
        head.* = .{};
        return null;
    }
    head.* = entry.next_sibling;
    entry.next_sibling = .{};
    entry.parent = .{};
    return popped;
}

/// Release the subtree rooted at `root_link`. DFS — descend into
/// `first_child` first, then process the node. The node is `release`d
/// per type, then `clearAndFreeSlot`d.
///
/// `caller_dom` is the calling domain's `*CapabilityDomain`, kept
/// locked throughout `revoke`. Used to skip a re-lock when a descendant
/// happens to live in the calling domain.
fn releaseSubtree(root: HandleLink, caller_dom: *CapabilityDomain) void {
    if (root.domain.ptr == null) return;

    const same_caller = root.domain.ptr == @as(*anyopaque, @ptrCast(caller_dom));
    const dom: *CapabilityDomain = if (same_caller) caller_dom else (root.domain.lockTyped(CapabilityDomain) catch return);
    defer if (!same_caller) root.domain.unlockTyped(CapabilityDomain);

    if (@as(u16, root.slot) >= capability.MAX_HANDLES_PER_DOMAIN) return;
    const slot: u12 = @intCast(root.slot);
    const entry = &dom.kernel_table[slot];
    if (entry.ref.ptr == null) return;

    // Recurse into children first.
    const child_head = entry.first_child;
    entry.first_child = .{};
    releaseSiblingChain(child_head, caller_dom);

    capability.releaseHandle(dom, slot, entry);
    capability.clearAndFreeSlot(dom, slot, entry);
}

/// Replace any link in `parent_entry.first_child` that names
/// `(target_dom, target_slot)` with `replacement`. Walks the
/// sibling chain by snapshotting each link, locking its holder, and
/// patching in place. If `replacement` is empty, the link is dropped
/// (the chain seams shut around it).
///
/// `held` names a domain whose gen-lock the caller already holds; the
/// walk skips re-acquisition for links that name it.
fn replaceLinkInChildList(
    parent_entry: *KernelHandle,
    target_dom: *CapabilityDomain,
    target_slot: u12,
    replacement: HandleLink,
    held: ?*CapabilityDomain,
) void {
    if (linkMatches(parent_entry.first_child, target_dom, target_slot)) {
        parent_entry.first_child = replacement;
        return;
    }

    var prev_link = parent_entry.first_child;
    var depth: u32 = 0;
    while (prev_link.domain.ptr != null) {
        std.debug.assert(depth < MAX_DEPTH);
        const prev = lockEntrySkip(prev_link, held) orelse return;

        if (linkMatches(prev.entry.next_sibling, target_dom, target_slot)) {
            prev.entry.next_sibling = replacement;
            unlockEntrySkip(prev, held);
            return;
        }

        const next = prev.entry.next_sibling;
        unlockEntrySkip(prev, held);
        prev_link = next;
        depth += 1;
    }
}

/// Identity check: link names `(dom, slot)`.
inline fn linkMatches(link: HandleLink, dom: *CapabilityDomain, slot: u12) bool {
    return link.domain.ptr == @as(*anyopaque, @ptrCast(dom)) and
        @as(u12, @intCast(link.slot)) == slot;
}

/// Cheap structural check — `entry` is well-formed and sits in the
/// used state of the kernel table. Always-on (does not get compiled
/// out). Used as the entry-gate for both `derive` and `revoke`.
fn assertInTree(entry: *const KernelHandle) void {
    std.debug.assert(entry.ref.ptr != null);
    if (entry.parent.domain.ptr != null) {
        std.debug.assert(@as(u16, entry.parent.slot) < capability.MAX_HANDLES_PER_DOMAIN);
    }
    if (entry.first_child.domain.ptr != null) {
        std.debug.assert(@as(u16, entry.first_child.slot) < capability.MAX_HANDLES_PER_DOMAIN);
    }
    if (entry.next_sibling.domain.ptr != null) {
        std.debug.assert(@as(u16, entry.next_sibling.slot) < capability.MAX_HANDLES_PER_DOMAIN);
    }
}

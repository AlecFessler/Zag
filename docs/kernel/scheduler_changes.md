# Zag Microkernel — Scheduler Design Changes

This document describes the scheduling system being added to Zag. It covers what is changing from the existing design and what is being added fresh. The agents updating the spec and systems docs should use this as the source of truth for what to write — they decide how to structure and word the actual document changes.

---

## Overview

The existing scheduler is a flat per-core FIFO run queue with a sentinel node, round-robin among all threads with no priority concept. This is being replaced with a five-level priority scheduler with work stealing, priority-ordered futex wakes, priority-ordered IPC queuing, and a unified exclusive core pinning mechanism. The `pin_exclusive` syscall is removed and replaced by `set_priority`.

---

## Priority Levels

There are five priority levels, represented as a u3 enum:

- `idle` (0) — only runs when no other thread is ready on any core
- `normal` (1) — the default for all newly created threads, round-robin among peers
- `high` (2) — preempts normal, round-robin among peers
- `realtime` (3) — preempts high and below, round-robin among peers
- `pinned` (4) — non-preemptible, exclusive core ownership

All newly created threads start at `normal`, including the initial thread of a new process. Priority inheritance is not implemented and is a known limitation.

---

## max_thread_priority

Every process has a `max_thread_priority: Priority` field. This is the ceiling — threads in that process cannot set their own priority above it. It is set at `proc_create` time as an explicit parameter; it is never implicitly inherited. A parent cannot grant a child a higher `max_thread_priority` than its own. Root service starts at `pinned`. The `pin_exclusive` ProcessRights bit is removed entirely — `max_thread_priority` at the `pinned` level replaces it as the capability gate.

The `set_affinity` ProcessRights bit remains and gates whether a thread can call `set_affinity` at all.

---

## set_priority

`set_priority(priority)` is self-only. A thread can only set its own priority. There is no thread handle parameter. This is consistent with `thread_exit` and `thread_yield` being self-only. The reason thread handles are not used is that a debugger owns thread handles for a debuggee's threads — if `set_priority` took a thread handle, a thread being debugged would be unable to set its own priority since it doesn't own its handles while a debugger is attached.

`set_priority` is gated on both `ProcessRights.set_affinity` (process-level permission to do scheduling operations at all) and the `max_thread_priority` ceiling (determines how high you can go).

For non-pinned levels, `set_priority` just updates the thread's priority and takes effect at the next scheduling decision.

For `pinned`, the behavior is more complex — see the Pinned Priority section below.

---

## set_affinity

`set_affinity(core_mask)` is also self-only for the same reason as `set_priority`. The thread handle parameter is removed. `ThreadHandleRights` loses the `set_affinity` bit entirely since no syscall uses it anymore. `set_affinity` is gated on `ProcessRights.set_affinity`.

---

## ThreadHandleRights Changes

`set_affinity` is removed from `ThreadHandleRights`. The remaining bits are `suspend`, `resume`, and `kill`. The rights type now has only 3 meaningful bits.

---

## Pinned Priority and Core Exclusivity

`pinned` is the highest priority level and means the thread is non-preemptible and exclusively owns a CPU core. This replaces the `pin_exclusive` syscall entirely.

To become pinned, a thread calls `set_priority(.pinned)`. The kernel scans the calling thread's current affinity mask in ascending core ID order looking for a core that has no current pinned owner. The first available core is claimed — the thread becomes the exclusive owner of that core, a core_pin handle is inserted into the process's permissions table, and the syscall returns the core_pin handle ID. If all cores in the affinity mask are already owned by pinned threads, the syscall returns `E_BUSY`. If the affinity mask is empty, it returns `E_INVAL`.

The affinity mask set before calling `set_priority(.pinned)` serves as the ordered candidate list. The thread sets its desired candidate cores via `set_affinity`, then calls `set_priority(.pinned)`, and the kernel picks the first available.

A pinned thread cannot call `set_affinity` — the affinity mask is locked while pinned. Attempting it returns `E_BUSY`.

There are two ways to unpin:

1. **Explicit**: call `revoke_perm` on the core_pin handle. This releases exclusive core ownership, restores the thread's pre-pin affinity mask, and drops the thread's priority back to whatever it was before `set_priority(.pinned)` was called.

2. **Implicit**: call `set_priority` with any non-pinned level. The kernel revokes the core_pin handle as a side effect, releases the core, restores affinity, then applies the new priority.

The core_pin handle is a revocation token only. It carries no rights bits (rights = 0). The only syscall that accepts it as input is `revoke_perm`. Its user view entry encodes `field0 = core_id`, `field1 = 0`. The thread_tid field that the old spec had in field1 is removed — threads are now first-class perm table objects, so that information is redundant.

Core_pin handles do NOT persist across process restart. They are cleared on restart alongside thread handles and VM reservation handles. This is a change from the old spec which listed core_pin as persisting (§2.6.13) — that was wrong since the pinned thread is dead after restart.

---

## Pinned Thread Blocking Behavior

When a pinned thread blocks (on a futex or IPC recv), it temporarily releases its core. Other threads may execute on that core via work stealing while the pinned thread is blocked. The pin relationship persists — the core is still "owned" by the pinned thread — but the core goes productive rather than sitting idle.

When the pinned thread becomes ready again (woken by futex_wake or IPC delivery), the kernel immediately sends an IPI to the designated core. Whatever thread is currently running on that core is preempted mid-timeslice regardless of its priority. The preempted thread is migrated to an affinity-eligible non-pinned core if one exists. If no eligible core exists, the thread remains in the pinned core's run queue and will only be scheduled again when the pinned thread next blocks.

A pinned core is never a target for proactive enqueue from other cores. Threads are only placed on a pinned core's run queue via work stealing, which is initiated by the pinned core itself when it goes idle.

---

## Priority Queue Data Structure

All three thread queue structures — run queues, futex buckets, and IPC wait queues — currently use a singly-linked intrusive list via `Thread.next`. All three are replaced with a unified `PriorityQueue` data structure that lives in `kernel/containers/priority_queue.zig`.

The `PriorityQueue` has 5 per-level FIFO queues (one per priority level), each with a head and tail pointer. Enqueueing appends to the tail of the thread's level. Dequeueing scans from level 4 down to level 0 and pops the head of the first non-empty level. FIFO order is preserved within each level. The structure has no locks — callers hold their own locks as before. It operates on `Thread.next` directly, same as the current intrusive list approach.

An additional method `peekHighestStealable(core_id)` scans levels 4→0 and returns the first thread whose affinity mask includes `core_id` and which is not a pinned thread. This is called without holding a lock — the result is advisory only.

`Thread.next` continues to be the intrusive pointer used for list membership. A thread is in at most one queue at a time, so sharing the field across all three queue types remains safe.

---

## Run Queue Changes

The per-core `RunQueue` wraps `PriorityQueue`. The sentinel node approach is removed. The idle thread is a real thread at priority `idle` re-enqueued after every timeslice when no real work exists.

`PerCoreState` gains a `pinned_thread: ?*Thread` field tracking which thread (if any) currently owns this core exclusively.

The scheduler timer handler changes to:
- If the pinned thread for this core is ready and not currently running: immediately preempt the current thread, attempt to migrate it, and switch to the pinned thread.
- If the current thread is the pinned thread: never preempt, just re-arm the timer.
- Otherwise: normal priority-aware round-robin. If a higher priority thread is ready, preempt. If same priority, re-enqueue current and switch. If current is highest, keep running.

When any thread becomes ready (futex wake, IPC delivery, thread_resume), if its priority exceeds the currently running thread on an affinity-eligible non-pinned core, send an IPI immediately rather than waiting for the next timer tick.

---

## Work Stealing

When a core's run queue is empty after dequeueing, it attempts to steal work. The steal algorithm:

1. Perform a non-locking peek across all other cores using `peekHighestStealable` to find the highest priority eligible thread across all cores.
2. Once the best candidate and its home core are identified, lock that core's run queue and attempt to remove the candidate.
3. If the candidate is still there, take it and return.
4. If it was removed between peek and lock (another core stole it or it was scheduled), retry the entire scan from the beginning.

Pinned cores are skipped entirely during work stealing — never steal from a pinned core's queue and never identify a pinned core as a target.

Work stealing is purely reactive — it only happens when a core goes idle. There is no background balancing. Topology is flat; NUMA and cache domain awareness are not implemented and are noted as future work.

---

## Futex Priority Ordering

The existing spec says futex waiters are woken in FIFO order (§2.5.7). This changes to: waiters are woken in priority order, with FIFO ordering within the same priority level. The futex `Bucket` struct replaces its intrusive list with a `PriorityQueue`.

---

## IPC Wait Queue Priority Ordering

The IPC call wait queue in `MessageBox` replaces its `waiters_head`/`waiters_tail` intrusive list with a `PriorityQueue`. Higher priority callers are served before lower priority callers. Within the same priority level, FIFO order is preserved. This means a realtime thread calling a server jumps ahead of normal priority callers already queued.

---

## Deferred Thread Cleanup Rename

The `Zombie` struct in `PerCoreState` is renamed to `ExitedThread`. The field `PerCoreState.zombie` is renamed to `PerCoreState.exited_thread`. Semantics are identical — this is a naming-only change to avoid confusion with the process zombie concept.

---

## Removed Syscall: pin_exclusive

`pin_exclusive` (§4.15) is removed entirely. Its functionality is replaced by `set_priority(.pinned)`. The spec should note that this syscall no longer exists.

## New Syscall: set_priority

`set_priority(priority)` is a new self-only syscall. It requires `ProcessRights.set_affinity` and checks `max_thread_priority`. For non-pinned levels it returns `E_OK`. For pinned it returns the core_pin handle ID on success, `E_BUSY` if no affinity-eligible core is available, `E_INVAL` if the affinity mask is empty, or `E_MAXCAP` if the permissions table is full. Setting a non-pinned priority while currently pinned implicitly unpins as a side effect.

## Changed Syscall: set_affinity

`set_affinity` loses its thread handle parameter and becomes self-only. It returns `E_BUSY` if the calling thread is currently pinned.

## Changed Syscall: proc_create

`proc_create` gains a `max_thread_priority: Priority` parameter. It is always required. Returns `E_PERM` if it exceeds the parent's own `max_thread_priority`. Returns `E_INVAL` if it is not a valid Priority value.

## Changed Syscall: thread_create

No change to the syscall itself. Newly created threads always start at `normal` priority.

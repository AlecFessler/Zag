const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const futex = zag.proc.futex;
const process_mod = zag.proc.process;
const sched = zag.sched.scheduler;

const Priority = zag.sched.thread.Priority;
const Process = zag.proc.process.Process;
const State = zag.sched.thread.State;
const Thread = zag.sched.thread.Thread;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const VAddr = zag.memory.address.VAddr;

const E_BADADDR = errors.E_BADADDR;
const E_BADCAP = errors.E_BADCAP;
const E_BUSY = errors.E_BUSY;
const E_INVAL = errors.E_INVAL;
const E_MAXCAP = errors.E_MAXCAP;
const E_MAXTHREAD = errors.E_MAXTHREAD;
const E_NOMEM = errors.E_NOMEM;
const E_NORES = errors.E_NORES;
const E_OK = errors.E_OK;
const E_PERM = errors.E_PERM;

pub fn sysThreadCreate(entry_addr: u64, arg: u64, num_stack_pages_u64: u64) i64 {
    if (num_stack_pages_u64 == 0 or num_stack_pages_u64 > std.math.maxInt(u32)) return E_INVAL;
    const num_stack_pages: u32 = @intCast(num_stack_pages_u64);

    if (!address.AddrSpacePartition.user.contains(entry_addr)) return E_BADADDR;

    const proc = sched.currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().spawn_thread) return E_PERM;

    const thread = Thread.create(proc, VAddr.fromInt(entry_addr), arg, num_stack_pages) catch |e| return switch (e) {
        error.MaxThreads => E_MAXTHREAD,
        error.OutOfKernelStacks => E_NORES,
        else => E_NOMEM,
    };

    // Insert thread handle into process perm table
    const handle_id = proc.insertThreadHandle(thread, proc.thread_handle_rights) catch {
        thread.deinit();
        return E_MAXCAP;
    };

    // If external fault handler, also insert into handler's perm table.
    // §2.12.5: the handle MUST be inserted; if the handler's table is full,
    // roll back the new thread and return E_MAXCAP so userspace observes
    // the failure instead of silently getting an unmanaged thread.
    if (proc.fault_handler_proc) |handler| {
        if (handler.insertThreadHandle(thread, ThreadHandleRights.full)) |_| {
            // OK
        } else |_| {
            proc.removePerm(handle_id) catch {};
            thread.deinit();
            return E_MAXCAP;
        }
    }

    sched.enqueueOnCore(arch.coreID(), thread);
    return @intCast(handle_id);
}

pub fn sysThreadExit() noreturn {
    const thread = sched.currentThread().?;
    thread.state = .exited;
    arch.enableInterrupts();
    sched.yield();
    while (true) {
        arch.enableInterrupts();
        arch.halt();
    }
}

pub fn sysThreadYield() i64 {
    arch.enableInterrupts();
    sched.yield();
    return E_OK;
}

pub fn sysSetAffinity(core_mask: u64) i64 {
    if (core_mask == 0) return E_INVAL;
    const count = arch.coreCount();
    const valid_mask: u64 = if (count >= 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(count)) - 1;
    if (core_mask & ~valid_mask != 0) return E_INVAL;

    const proc = sched.currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().set_affinity) return E_PERM;

    const thread = sched.currentThread().?;
    // Cannot change affinity while pinned
    if (thread.priority == .pinned) return E_BUSY;

    thread.core_affinity = core_mask;
    return E_OK;
}

pub fn sysSetPriority(priority_raw: u64) i64 {
    if (priority_raw > 4) return E_INVAL;
    const new_priority: Priority = @enumFromInt(@as(u3, @truncate(priority_raw)));

    const proc = sched.currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().set_affinity) return E_PERM;

    const thread = sched.currentThread().?;

    // Check against process ceiling
    if (@intFromEnum(new_priority) > @intFromEnum(proc.max_thread_priority)) return E_PERM;

    const currently_pinned = thread.priority == .pinned;

    if (new_priority == .pinned) {
        const count = arch.coreCount();
        const all_cores: u64 = if (count >= 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(count)) - 1;
        const affinity = thread.core_affinity orelse all_cores;
        if (affinity == 0) return E_INVAL;

        // Save pre-pin state before modifying
        thread.pre_pin_priority = thread.priority;
        thread.pre_pin_affinity = thread.core_affinity;

        // Find a single core in the affinity mask
        var mask = affinity;
        while (mask != 0) {
            const core_idx: u6 = @truncate(@ctz(mask));
            const core_bit = @as(u64, 1) << core_idx;

            // Set single-core affinity for pinExclusive
            thread.core_affinity = core_bit;
            const pin_result = sched.pinExclusive(thread);
            if (pin_result >= 0) {
                thread.priority = .pinned;
                // Sync user view so thread entry field1 reflects pinned core
                proc.perm_lock.lock();
                proc.syncUserView();
                proc.perm_lock.unlock();
                return pin_result;
            }

            // This core was busy, try next one in mask
            mask &= ~core_bit;
        }

        // All affinity cores have pinned owners
        thread.core_affinity = affinity;
        return E_BUSY;
    }

    // Non-pinned priority level
    if (currently_pinned) {
        // Implicitly unpin: restore affinity, then apply new priority
        sched.unpinByRevoke(@ctz(thread.core_affinity orelse 0));
    }

    thread.priority = new_priority;
    return E_OK;
}

pub fn sysThreadSelf() i64 {
    const proc = sched.currentProc();
    const thread = sched.currentThread().?;
    if (proc.findThreadHandle(thread)) |handle_id| {
        return @intCast(handle_id);
    }
    return E_INVAL;
}

pub fn sysThreadSuspend(thread_handle: u64) i64 {
    const proc = sched.currentProc();
    const thr_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thr_entry.object != .thread) return E_BADCAP;
    if (!thr_entry.threadHandleRights().@"suspend") return E_PERM;

    const target = thr_entry.object.thread;
    const target_proc = target.process;

    target_proc.lock.lock();

    switch (target.state) {
        .faulted, .suspended => {
            target_proc.lock.unlock();
            return E_BUSY;
        },
        .exited => {
            target_proc.lock.unlock();
            return E_BADCAP;
        },
        // §2.4: blocked threads (futex / IPC) cannot be suspended in
        // place — the wake path would race with the suspend and re-mark
        // the thread .ready, defeating the suspend. Reject with E_BUSY;
        // a debugger can wait for the thread to leave .blocked and try
        // again.
        .blocked => {
            target_proc.lock.unlock();
            return E_BUSY;
        },
        .running, .ready => {
            target.state = .suspended;
            target_proc.suspended_thread_slots |= @as(u64, 1) << @intCast(target.slot_index);

            const cur = sched.currentThread().?;
            if (target == cur) {
                // Self-suspend: we must deschedule now, before returning
                // to userspace. If we merely marked ourselves .suspended
                // and returned, we would keep executing user code until
                // the next preemption (up to a full timeslice), and a
                // concurrent thread_resume from another core could
                // re-enqueue us while we are still running on this core
                // — dual dispatch. §2.4.9 requires the transition to be
                // effective immediately.
                target_proc.lock.unlock();
                arch.enableInterrupts();
                sched.yield();
                // On the next time we are resumed, we return into the
                // syscall epilogue with rax = E_OK.
                return E_OK;
            }

            target_proc.lock.unlock();

            // The target may be in a run queue (.ready) or actively
            // dispatched on a core (.running). Because the scheduler
            // transitions .ready → .running without holding proc.lock,
            // there is a TOCTOU race: the thread could have been
            // dispatched between our state check and our write. Handle
            // both cases: remove from any run queue (covers .ready /
            // just-preempted), then IPI the core if it is on-cpu.
            sched.removeFromAnyRunQueue(target);

            if (sched.coreRunning(target)) |core_id| {
                arch.triggerSchedulerInterrupt(core_id);
            }
            return E_OK;
        },
    }
    target_proc.lock.unlock();
    return E_OK;
}

pub fn sysThreadResume(thread_handle: u64) i64 {
    const proc = sched.currentProc();
    const thr_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thr_entry.object != .thread) return E_BADCAP;
    if (!thr_entry.threadHandleRights().@"resume") return E_PERM;

    const target = thr_entry.object.thread;
    const target_proc = target.process;

    target_proc.lock.lock();
    if (target.state != .suspended) {
        target_proc.lock.unlock();
        return E_INVAL;
    }

    target.state = .ready;
    target_proc.suspended_thread_slots &= ~(@as(u64, 1) << @intCast(target.slot_index));
    target_proc.lock.unlock();

    const target_core = if (target.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
    sched.enqueueOnCore(target_core, target);
    return E_OK;
}

pub fn sysThreadKill(thread_handle: u64) i64 {
    const proc = sched.currentProc();
    const thr_entry = proc.getPermByHandle(thread_handle) orelse return E_BADCAP;
    if (thr_entry.object != .thread) return E_BADCAP;
    if (!thr_entry.threadHandleRights().kill) return E_PERM;

    const target = thr_entry.object.thread;
    const target_proc = target.process;
    const cur = sched.currentThread().?;

    target_proc.lock.lock();
    if (target.state == .faulted) {
        target_proc.lock.unlock();
        return E_BUSY;
    }
    if (target.state == .exited) {
        target_proc.lock.unlock();
        return E_BADCAP;
    }

    const was_running = target.state == .running;
    const is_self = target == cur;
    // Use atomic store so concurrent wakeThread's cmpxchg on
    // thread.state observes .exited and skips the wake.
    const state_ptr: *align(1) u8 = @ptrCast(&target.state);
    @atomicStore(u8, state_ptr, @intFromEnum(State.exited), .release);
    // Clear bitmask bits
    target_proc.faulted_thread_slots &= ~(@as(u64, 1) << @intCast(target.slot_index));
    target_proc.suspended_thread_slots &= ~(@as(u64, 1) << @intCast(target.slot_index));
    target_proc.lock.unlock();

    // Self-kill: fall through to scheduler-zombie cleanup path.
    if (is_self) {
        arch.enableInterrupts();
        sched.yield();
        while (true) arch.halt();
    }

    // If running on another core, IPI it; scheduler picks it up as zombie.
    // Use coreRunning() to find the actual core (not the affinity mask),
    // which handles multi-core affinity and null-affinity threads correctly.
    if (was_running) {
        if (sched.coreRunning(target)) |core_id| {
            arch.triggerSchedulerInterrupt(core_id);
        }
        return E_OK;
    }

    // Off-CPU. If .ready, remove from run queue first to avoid dangling.
    sched.removeFromAnyRunQueue(target);
    if (target.futex_paddr.addr != 0) futex.removeBlockedThread(target);
    // If the target was .blocked inside ipc_call, it still has a back-
    // pointer into some other process's msg_box (either as the pending
    // reply target or queued on the wait list). deinit() does not walk
    // those structures, so without this scrub the msg_box would be left
    // holding a dangling *Thread — the same UAF class that scrubFromFaultBox
    // fixes for the fault box. Mirrors Process.kill()'s blocked-thread
    // cleanup loop.
    if (target.ipc_server) |server| {
        server.msg_box.lock.lock();
        if (server.msg_box.isPendingReply() and server.msg_box.pending_thread == target) {
            _ = server.msg_box.endPendingReplyLocked();
        } else {
            _ = server.msg_box.removeLocked(target);
        }
        target.ipc_server = null;
        server.msg_box.lock.unlock();
    }
    // Also scrub from our own msg_box in case target was the blocked
    // receiver (a dying recv()er), and from our own / handler's fault
    // boxes in case target was queued there for some reason. These are
    // cheap no-ops when the thread isn't actually in the box.
    target_proc.msg_box.lock.lock();
    if (target_proc.msg_box.isReceiving() and target_proc.msg_box.receiver == target) {
        _ = target_proc.msg_box.takeReceiverLocked();
    }
    _ = target_proc.msg_box.removeLocked(target);
    target_proc.msg_box.lock.unlock();
    process_mod.scrubFromFaultBoxPub(&target_proc.fault_box, target);
    if (target_proc.fault_handler_proc) |handler| {
        process_mod.scrubFromFaultBoxPub(&handler.fault_box, target);
    }
    // deinit removes thread handles from perm tables, frees stacks,
    // calls lastThreadExited (which triggers process exit/restart).
    target.deinit();

    return E_OK;
}


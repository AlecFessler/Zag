const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const sched = zag.sched.scheduler;

const isSubset = zag.perms.permissions.isSubset;

const ArchCpuContext = zag.arch.dispatch.ArchCpuContext;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Process = zag.proc.process.Process;
const ProcessHandleRights = zag.perms.permissions.ProcessHandleRights;
const SharedMemory = zag.memory.shared.SharedMemory;
const State = zag.sched.thread.State;
const SyscallResult = zag.syscall.dispatch.SyscallResult;
const Thread = zag.sched.thread.Thread;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;

const E_AGAIN = errors.E_AGAIN;
const E_BADCAP = errors.E_BADCAP;
const E_BUSY = errors.E_BUSY;
const E_INVAL = errors.E_INVAL;
const E_MAXCAP = errors.E_MAXCAP;
const E_OK = errors.E_OK;
const E_PERM = errors.E_PERM;

const IpcMetadata = struct {
    word_count: u3,
    cap_transfer: bool,
};

fn parseIpcMetadata(raw: u64) IpcMetadata {
    return .{
        .word_count = @truncate(raw & 0x7),
        .cap_transfer = (raw & 0x8) != 0,
    };
}

fn transferCapability(sender_proc: *Process, target_proc: *Process, handle_val: u64, rights_val: u64) i64 {
    sender_proc.perm_lock.lock();
    const src_entry = sender_proc.getPermByHandleLocked(handle_val) orelse {
        sender_proc.perm_lock.unlock();
        return E_BADCAP;
    };

    switch (src_entry.object) {
        .shared_memory => |shm| {
            if (!src_entry.shmRights().grant) {
                sender_proc.perm_lock.unlock();
                return E_PERM;
            }
            const granted_u16: u16 = @truncate(rights_val);
            if (!isSubset(granted_u16, src_entry.rights)) {
                sender_proc.perm_lock.unlock();
                return E_PERM;
            }
            // Safe: perm_lock held, so revoke can't removePerm+decRef yet.
            shm.incRef();
            sender_proc.perm_lock.unlock();

            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .shared_memory = shm },
                .rights = granted_u16,
            };
            _ = target_proc.insertPerm(new_entry) catch {
                shm.decRef();
                return E_MAXCAP;
            };
            return E_OK;
        },
        .process => |proc_ptr| {
            if (handle_val == 0) {
                sender_proc.perm_lock.unlock();
                // Sending HANDLE_SELF: gives recipient a process handle to the sender.
                const granted_u16: u16 = @truncate(rights_val);
                const granted_phr: ProcessHandleRights = @bitCast(granted_u16);

                // If fault_handler bit is set, handle the fault_handler transfer.
                // §2.12.3 requires the routing change to be atomic so a fault
                // in between cannot observe "no handler" and kill the sender.
                //
                // `faultHandlerOf` consults `fault_handler_proc` first and
                // only falls back to the slot-0 bit when that is null, so
                // the safe ordering is:
                //   1. set fault_handler_proc = target
                //   2. clear the slot-0 fault_handler bit
                // During the gap, a fault routes to `target` (its eventual
                // destination). Both writes happen under sender_proc.lock
                // (which protects fault_handler_proc per process.zig:87),
                // nested with perm_lock for the slot-0 bit write.
                if (granted_phr.fault_handler) {
                    sender_proc.lock.lock();
                    sender_proc.fault_handler_proc = target_proc;
                    sender_proc.perm_lock.lock();
                    const self_rights = sender_proc.perm_table[0].processRights();
                    sender_proc.had_self_fault_handler = self_rights.fault_handler;
                    var new_rights = self_rights;
                    new_rights.fault_handler = false;
                    sender_proc.perm_table[0].rights = @bitCast(new_rights);
                    sender_proc.syncUserView();
                    sender_proc.perm_lock.unlock();
                    sender_proc.lock.unlock();

                    // Link sender into target's fault_handler_targets list
                    // so target's death can revert sender to self-handling.
                    // If target died in the window between our writes above
                    // and now, its cleanupPhase1 has already walked an empty
                    // list and will never unlink us. Roll back the transfer:
                    // restore sender's slot-0 fault_handler bit and clear
                    // fault_handler_proc so sender goes back to self-handling.
                    if (!target_proc.linkFaultHandlerTarget(sender_proc)) {
                        sender_proc.lock.lock();
                        sender_proc.fault_handler_proc = null;
                        sender_proc.perm_lock.lock();
                        const r = sender_proc.perm_table[0].processRights();
                        var rr = r;
                        rr.fault_handler = true;
                        sender_proc.perm_table[0].rights = @bitCast(rr);
                        sender_proc.syncUserView();
                        sender_proc.perm_lock.unlock();
                        sender_proc.lock.unlock();
                        return E_INVAL;
                    }

                    // Check if target already has a handle to sender, add fault_handler bit
                    target_proc.perm_lock.lock();
                    var found_existing = false;
                    for (&target_proc.perm_table) |*slot| {
                        if (slot.object == .process and slot.object.process == proc_ptr) {
                            var existing_rights: ProcessHandleRights = @bitCast(slot.rights);
                            existing_rights.fault_handler = true;
                            slot.rights = @bitCast(existing_rights);
                            found_existing = true;
                            break;
                        }
                    }
                    target_proc.perm_lock.unlock();

                    if (!found_existing) {
                        _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Add, 1, .acq_rel);
                        _ = target_proc.insertPerm(.{
                            .handle = 0,
                            .object = .{ .process = proc_ptr },
                            .rights = granted_u16,
                        }) catch {
                            _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Sub, 1, .acq_rel);
                            return E_MAXCAP;
                        };
                    }

                    // Snapshot the sender's thread list under sender_proc.lock,
                    // then release the lock before walking it (insertThreadHandle
                    // takes target_proc.perm_lock and we don't want to nest).
                    sender_proc.lock.lock();
                    const num_threads = sender_proc.num_threads;
                    var threads_copy: [Process.MAX_THREADS]*Thread = undefined;
                    @memcpy(threads_copy[0..num_threads], sender_proc.threads[0..num_threads]);
                    sender_proc.lock.unlock();

                    for (threads_copy[0..num_threads]) |t| {
                        _ = target_proc.insertThreadHandle(t, ThreadHandleRights.full) catch {};
                    }

                    target_proc.syncUserView();
                    return E_OK;
                }

                // Normal HANDLE_SELF transfer (no fault_handler)
                const new_entry = PermissionEntry{
                    .handle = 0,
                    .object = .{ .process = proc_ptr },
                    .rights = granted_u16,
                };
                _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Add, 1, .acq_rel);
                _ = target_proc.insertPerm(new_entry) catch {
                    _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Sub, 1, .acq_rel);
                    return E_MAXCAP;
                };
                return E_OK;
            }
            // perm_lock still held — prevents concurrent revoke/decRef
            // from racing with the refcount bump below (TOCTOU mirror
            // of the SHM arm above).
            if (!src_entry.processHandleRights().grant) {
                sender_proc.perm_lock.unlock();
                return E_PERM;
            }
            const granted_u16: u16 = @truncate(rights_val);
            if (!isSubset(granted_u16, src_entry.rights)) {
                sender_proc.perm_lock.unlock();
                return E_PERM;
            }
            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .process = proc_ptr },
                .rights = granted_u16,
            };
            _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Add, 1, .acq_rel);
            sender_proc.perm_lock.unlock();
            _ = target_proc.insertPerm(new_entry) catch {
                _ = @atomicRmw(u32, &proc_ptr.handle_refcount, .Sub, 1, .acq_rel);
                return E_MAXCAP;
            };
            return E_OK;
        },
        .device_region => |device| {
            sender_proc.perm_lock.unlock();
            if (!src_entry.deviceRights().grant) return E_PERM;
            const granted_u16: u16 = @truncate(rights_val);
            if (!isSubset(granted_u16, src_entry.rights)) return E_PERM;
            // Device transfer is parent->child only
            if (target_proc.parent != sender_proc) return E_PERM;
            const target_self = target_proc.getPermByHandle(0) orelse return E_PERM;
            if (!target_self.processRights().device_own) return E_PERM;
            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .device_region = device },
                .rights = granted_u16,
            };
            _ = target_proc.insertPerm(new_entry) catch return E_MAXCAP;
            sender_proc.removePerm(handle_val) catch {};
            return E_OK;
        },
        .thread => {
            // Thread handles are not transferable via IPC
            sender_proc.perm_lock.unlock();
            return E_PERM;
        },
        else => {
            sender_proc.perm_lock.unlock();
            return E_INVAL;
        },
    }
}

/// Get payload registers for cap transfer (last 2 of N words)
fn getCapPayload(ctx: *const ArchCpuContext, word_count: u3) struct { handle: u64, rights: u64 } {
    const payload_regs = arch.getIpcPayloadWords(ctx);
    if (word_count < 2) return .{ .handle = 0, .rights = 0 };
    return .{
        .handle = payload_regs[word_count - 2],
        .rights = payload_regs[word_count - 1],
    };
}

fn validateIpcSendRights(entry: PermissionEntry, meta: IpcMetadata, sender_proc: *Process, src_ctx: *const ArchCpuContext) i64 {
    const rights = entry.processHandleRights();
    if (!rights.send_words) return E_PERM;
    if (meta.cap_transfer) {
        if (meta.word_count < 2) return E_INVAL;
        const cap = getCapPayload(src_ctx, meta.word_count);
        const cap_entry = sender_proc.getPermByHandle(cap.handle) orelse return E_BADCAP;
        switch (cap_entry.object) {
            .shared_memory => if (!rights.send_shm) return E_PERM,
            .process => if (!rights.send_process) return E_PERM,
            .device_region => if (!rights.send_device) return E_PERM,
            else => return E_INVAL,
        }
    }
    return E_OK;
}

fn wakeThread(thread: *Thread) void {
    while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();

    // Atomically transition .blocked → .ready. If the thread has already
    // been marked .exited by a concurrent sysThreadKill, the cmpxchg
    // fails and we silently skip the wake — the killing core owns the
    // thread from that point and will call deinit(). Without this guard
    // we would enqueue a thread that is about to be freed, causing a
    // use-after-free when the scheduler dequeues it.
    const state_ptr: *align(1) u8 = @ptrCast(&thread.state);
    const old = @cmpxchgStrong(u8, state_ptr, @intFromEnum(State.blocked), @intFromEnum(State.ready), .acq_rel, .monotonic);
    if (old != null) return;

    const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
    sched.enqueueOnCore(target_core, thread);
}

pub fn sysIpcSend(ctx: *ArchCpuContext) SyscallResult {
    const thread = sched.currentThread().?;
    const proc = thread.process;
    const target_handle = arch.getIpcHandle(ctx);
    const meta = parseIpcMetadata(arch.getIpcMetadata(ctx));

    // Look up target process
    const target_entry = proc.getPermByHandle(target_handle) orelse return .{ .ret = E_BADCAP };
    if (target_entry.object != .process) return .{ .ret = E_BADCAP };
    const target_proc = target_entry.object.process;

    // §2.6.30: lazily convert dead process entries on IPC attempt.
    if (!target_proc.alive) {
        proc.convertToDeadProcess(target_proc);
        return .{ .ret = E_BADCAP };
    }

    // Validate rights
    const rights_check = validateIpcSendRights(target_entry, meta, proc, ctx);
    if (rights_check != E_OK) return .{ .ret = rights_check };

    target_proc.msg_box.lock.lock();

    if (!target_proc.msg_box.isReceiving()) {
        // No receiver waiting
        target_proc.msg_box.lock.unlock();
        return .{ .ret = E_AGAIN };
    }

    // Receiver is waiting — deliver directly
    const receiver = target_proc.msg_box.takeReceiverLocked();
    // Snapshot receiver regs that we're about to overwrite, so we can
    // restore them if cap transfer fails and the receiver re-blocks.
    const saved_return = arch.getSyscallReturn(receiver.ctx);
    const saved_meta = arch.getIpcMetadata(receiver.ctx);
    const saved_payload = arch.saveIpcPayload(receiver.ctx);
    arch.copyIpcPayload(receiver.ctx, ctx, meta.word_count);
    // Set recv metadata: bit 0 = 0 (from send), bits [3:1] = word_count
    arch.setIpcMetadata(receiver.ctx, @as(u64, meta.word_count) << 1);
    arch.setSyscallReturn(receiver.ctx, @bitCast(E_OK));

    // Handle capability transfer
    if (meta.cap_transfer) {
        const cap = getCapPayload(ctx, meta.word_count);
        const cap_result = transferCapability(proc, target_proc, cap.handle, cap.rights);
        if (cap_result != E_OK) {
            // Roll back: restore receiver ctx and re-block.
            arch.setSyscallReturn(receiver.ctx, saved_return);
            arch.setIpcMetadata(receiver.ctx, saved_meta);
            arch.restoreIpcPayload(receiver.ctx, saved_payload);
            target_proc.msg_box.beginReceivingLocked(receiver);
            target_proc.msg_box.lock.unlock();
            return .{ .ret = cap_result };
        }
    }

    // Send has no caller to reply to.
    target_proc.msg_box.beginPendingReplyLocked(null);
    target_proc.msg_box.lock.unlock();

    wakeThread(receiver);
    return .{ .ret = E_OK };
}

pub fn sysIpcCall(ctx: *ArchCpuContext) SyscallResult {
    const thread = sched.currentThread().?;
    const proc = thread.process;
    const target_handle = arch.getIpcHandle(ctx);
    const meta = parseIpcMetadata(arch.getIpcMetadata(ctx));

    const target_entry = proc.getPermByHandle(target_handle) orelse return .{ .ret = E_BADCAP };
    if (target_entry.object != .process) return .{ .ret = E_BADCAP };
    const target_proc = target_entry.object.process;

    // §2.6.30: lazily convert dead process entries on IPC attempt.
    if (!target_proc.alive) {
        proc.convertToDeadProcess(target_proc);
        return .{ .ret = E_BADCAP };
    }

    const rights_check = validateIpcSendRights(target_entry, meta, proc, ctx);
    if (rights_check != E_OK) return .{ .ret = rights_check };

    target_proc.msg_box.lock.lock();

    if (target_proc.msg_box.isReceiving()) {
        // Receiver is waiting — deliver and queue caller for reply.
        const receiver = target_proc.msg_box.takeReceiverLocked();
        const saved_return = arch.getSyscallReturn(receiver.ctx);
        const saved_meta = arch.getIpcMetadata(receiver.ctx);
        const saved_payload = arch.saveIpcPayload(receiver.ctx);
        arch.copyIpcPayload(receiver.ctx, ctx, meta.word_count);
        arch.setIpcMetadata(receiver.ctx, (@as(u64, meta.word_count) << 1) | 1); // bit 0 = 1 (from call)
        arch.setSyscallReturn(receiver.ctx, @bitCast(E_OK));

        if (meta.cap_transfer) {
            const cap = getCapPayload(ctx, meta.word_count);
            const cap_result = transferCapability(proc, target_proc, cap.handle, cap.rights);
            if (cap_result != E_OK) {
                // Roll back: restore receiver ctx and re-block.
                arch.setSyscallReturn(receiver.ctx, saved_return);
                arch.setIpcMetadata(receiver.ctx, saved_meta);
                arch.restoreIpcPayload(receiver.ctx, saved_payload);
                target_proc.msg_box.beginReceivingLocked(receiver);
                target_proc.msg_box.lock.unlock();
                return .{ .ret = cap_result };
            }
        }

        target_proc.msg_box.beginPendingReplyLocked(thread);
        thread.ipc_server = target_proc;
        target_proc.msg_box.lock.unlock();

        // TODO: this should switchToThread directly to the receiver as a
        // fast-path handoff, but doing so currently hangs. Use wakeThread
        // and block self via switchToNextReady for now.
        wakeThread(receiver);

        thread.state = .blocked;
        thread.ctx = ctx;
        thread.on_cpu.store(false, .release);
        sched.switchToNextReady();
    } else {
        // No receiver — queue on wait list
        target_proc.msg_box.enqueueLocked(thread);
        thread.ipc_server = target_proc;
        target_proc.msg_box.lock.unlock();

        thread.state = .blocked;
        // switchToNextReady saves ctx and never returns
        thread.ctx = ctx;
        thread.on_cpu.store(false, .release);
        sched.switchToNextReady();
        // Never reached — when reply wakes us, we resume from ctx (int 0x80 frame)
        // with reply data already in registers
    }
}

pub fn sysIpcRecv(ctx: *ArchCpuContext) SyscallResult {
    const thread = sched.currentThread().?;
    const proc = thread.process;
    const blocking = (arch.getIpcMetadata(ctx) & 0x2) != 0;

    proc.msg_box.lock.lock();

    // Must reply before receiving again.
    if (proc.msg_box.isPendingReply()) {
        proc.msg_box.lock.unlock();
        return .{ .ret = E_BUSY };
    }

    // Check if another thread is already receiving.
    if (proc.msg_box.isReceiving()) {
        proc.msg_box.lock.unlock();
        return .{ .ret = E_BUSY };
    }

    const waiter = proc.msg_box.dequeueLocked() orelse {
        if (!blocking) {
            proc.msg_box.lock.unlock();
            return .{ .ret = E_AGAIN };
        }
        // Block on recv.
        proc.msg_box.beginReceivingLocked(thread);
        proc.msg_box.lock.unlock();

        thread.state = .blocked;
        thread.ctx = ctx;
        thread.on_cpu.store(false, .release);
        sched.switchToNextReady();
        // Never reached — sender delivers message and wakes us via switchTo.
        return .{ .ret = E_OK };
    };

    // Copy payload from waiter's saved context.
    const waiter_meta = parseIpcMetadata(arch.getIpcMetadata(waiter.ctx));
    arch.copyIpcPayload(ctx, waiter.ctx, waiter_meta.word_count);

    // Set recv metadata: bit 0 = 1 (always from call — send doesn't queue).
    arch.setIpcMetadata(ctx, (@as(u64, waiter_meta.word_count) << 1) | 1);

    // Handle capability transfer.
    if (waiter_meta.cap_transfer) {
        const cap = getCapPayload(waiter.ctx, waiter_meta.word_count);
        const cap_result = transferCapability(waiter.process, proc, cap.handle, cap.rights);
        if (cap_result != E_OK) {
            // Put waiter back at head of the queue.
            proc.msg_box.enqueueFrontLocked(waiter);
            proc.msg_box.lock.unlock();
            return .{ .ret = cap_result };
        }
    }

    proc.msg_box.beginPendingReplyLocked(waiter);
    proc.msg_box.lock.unlock();

    return .{ .ret = E_OK };
}

pub fn sysIpcReply(ctx: *ArchCpuContext) SyscallResult {
    const thread = sched.currentThread().?;
    const proc = thread.process;
    const reply_meta = arch.getIpcMetadata(ctx);
    const atomic_recv = (reply_meta & 0x1) != 0;
    const recv_blocking = (reply_meta & 0x2) != 0;
    const reply_word_count: u3 = @truncate((reply_meta >> 2) & 0x7);
    const reply_cap_transfer = (reply_meta & 0x20) != 0;

    // §4.16.11: cap_transfer requires word_count >= 2 (payload carries
    // handle+rights in the last two words). Reject early before touching
    // msg_box state.
    if (reply_cap_transfer and reply_word_count < 2) {
        return .{ .ret = E_INVAL };
    }

    proc.msg_box.lock.lock();

    if (!proc.msg_box.isPendingReply()) {
        proc.msg_box.lock.unlock();
        return .{ .ret = E_INVAL };
    }

    const caller_thread: ?*Thread = proc.msg_box.endPendingReplyLocked();

    // Capability transfer runs before we commit any payload to the
    // caller: on failure, both caller and replier must observe the
    // error rather than a successful reply (§2.11.14). Preserve the
    // caller's original payload registers — only the return value is overwritten.
    var reply_cap_err: i64 = E_OK;
    if (caller_thread) |pc| {
        if (reply_cap_transfer) {
            const cap = getCapPayload(ctx, reply_word_count);
            reply_cap_err = transferCapability(proc, pc.process, cap.handle, cap.rights);
        }
        if (reply_cap_err != E_OK) {
            arch.setSyscallReturn(pc.ctx, @bitCast(reply_cap_err));
        } else {
            arch.copyIpcPayload(pc.ctx, ctx, reply_word_count);
            arch.setSyscallReturn(pc.ctx, @bitCast(E_OK));
            arch.setIpcMetadata(pc.ctx, (@as(u64, reply_word_count) << 1) | 1);
        }

        pc.ipc_server = null;
    }

    if (atomic_recv) {
        // Reply + recv atomically.
        if (proc.msg_box.dequeueLocked()) |waiter| {
            const waiter_meta = parseIpcMetadata(arch.getIpcMetadata(waiter.ctx));

            // Capability transfer runs before we deliver to the receiver:
            // on failure, put the waiter back at the head of the queue
            // and return E_MAXCAP (§2.11.14) — mirrors sysIpcRecv.
            if (waiter_meta.cap_transfer) {
                const cap = getCapPayload(waiter.ctx, waiter_meta.word_count);
                const cap_result = transferCapability(waiter.process, proc, cap.handle, cap.rights);
                if (cap_result != E_OK) {
                    proc.msg_box.enqueueFrontLocked(waiter);
                    proc.msg_box.lock.unlock();
                    if (caller_thread) |ct| wakeThread(ct);
                    return .{ .ret = cap_result };
                }
            }

            arch.copyIpcPayload(ctx, waiter.ctx, waiter_meta.word_count);
            arch.setIpcMetadata(ctx, (@as(u64, waiter_meta.word_count) << 1) | 1);
            arch.setSyscallReturn(ctx, @bitCast(E_OK));

            proc.msg_box.beginPendingReplyLocked(waiter);
            proc.msg_box.lock.unlock();

            if (caller_thread) |ct| wakeThread(ct);
            return .{ .ret = if (reply_cap_err != E_OK) reply_cap_err else E_OK };
        } else if (recv_blocking) {
            proc.msg_box.beginReceivingLocked(thread);
            proc.msg_box.lock.unlock();

            // TODO: same direct-switch hang issue as above; use wakeThread
            // for now and block self via switchToNextReady.
            if (caller_thread) |ct| wakeThread(ct);
            thread.state = .blocked;
            arch.setSyscallReturn(ctx, @bitCast(reply_cap_err));
            thread.ctx = ctx;
            thread.on_cpu.store(false, .release);
            sched.switchToNextReady();
            unreachable;
        } else {
            proc.msg_box.lock.unlock();
            if (caller_thread) |ct| wakeThread(ct);
            const recv_err = if (reply_cap_err != E_OK) reply_cap_err else E_AGAIN;
            arch.setSyscallReturn(ctx, @bitCast(recv_err));
            return .{ .ret = recv_err };
        }
    } else {
        proc.msg_box.lock.unlock();

        if (caller_thread == null) return .{ .ret = reply_cap_err };

        const ct = caller_thread.?;

        // Guard against concurrent sysThreadKill: if the caller thread
        // was already marked .exited, skip the wake entirely — the
        // killing core owns cleanup. Fall through to return normally.
        const ct_state_ptr: *align(1) u8 = @ptrCast(&ct.state);
        const ct_old = @cmpxchgStrong(u8, ct_state_ptr, @intFromEnum(State.blocked), @intFromEnum(State.ready), .acq_rel, .monotonic);
        if (ct_old != null) return .{ .ret = reply_cap_err };

        // Caller successfully transitioned to .ready — try direct switch.
        thread.state = .ready;
        arch.setSyscallReturn(ctx, @bitCast(reply_cap_err));
        const result = sched.switchToThread(thread, ct, ctx, true);
        if (result != 0) {
            thread.state = .running;
            // Already .ready from cmpxchg above, just enqueue.
            const target_core = if (ct.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
            sched.enqueueOnCore(target_core, ct);
            return .{ .ret = reply_cap_err };
        }
        unreachable;
    }
}

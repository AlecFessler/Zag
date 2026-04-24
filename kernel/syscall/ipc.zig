const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const kprof = zag.kprof.trace_id;
const process_mod = zag.proc.process;
const sched = zag.sched.scheduler;

const isSubset = zag.perms.permissions.isSubset;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;
const DeviceRegion = zag.memory.device_region.DeviceRegion;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Process = zag.proc.process.Process;
const ProcessHandleRights = zag.perms.permissions.ProcessHandleRights;
const SharedMemory = zag.memory.shared.SharedMemory;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
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
        .shared_memory => |shm_ref| {
            const shm = shm_ref.ptr;
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
                .object = .{ .shared_memory = process_mod.slabRefNow(SharedMemory, shm) },
                .rights = granted_u16,
            };
            _ = target_proc.insertPerm(new_entry) catch {
                shm.decRef();
                return E_MAXCAP;
            };
            return E_OK;
        },
        .process => |proc_ref| {
            const proc_ptr = proc_ref.ptr;
            if (handle_val == 0) {
                // Red-team Finding (5c80fe4): self-cap-transfer is a
                // no-op semantically and composes with the slot-0 rights
                // pun in validateIpcSendRights to yield a handle-table
                // corruption primitive. When target_proc == sender_proc
                // the fault_handler branch walks sender_proc.threads[]
                // and inserts duplicate thread handles into the sender's
                // own perm table. Reject outright.
                if (target_proc == sender_proc) {
                    sender_proc.perm_lock.unlock();
                    return E_INVAL;
                }
                // Sending HANDLE_SELF: gives recipient a process handle to the sender.
                // §4.1.2 restricts the `fault_handler` ProcessHandleRights bit to
                // "at most one external process per target" — and §4.1.3 describes
                // the transfer as moving a right the sender *held*. A sender that
                // does not currently hold `ProcessRights.fault_handler` on slot 0
                // cannot grant it away; doing so would let an unprivileged process
                // install an arbitrary receiver as its own fault handler, letting
                // the receiver acquire thread handles with full ThreadHandleRights
                // including `pmu` (§4.1.42). Reject with E_PERM — mirrors the
                // grant check in the SHM and external-process arms.
                const granted_u16: u16 = @truncate(rights_val);
                const granted_phr: ProcessHandleRights = @bitCast(granted_u16);
                if (granted_phr.fault_handler and !sender_proc.perm_table[0].processRights().fault_handler) {
                    sender_proc.perm_lock.unlock();
                    return E_PERM;
                }
                sender_proc.perm_lock.unlock();

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
                    sender_proc._gen_lock.lock();
                    sender_proc.fault_handler_proc = process_mod.slabRefNow(Process, target_proc);
                    sender_proc.perm_lock.lock();
                    const self_rights = sender_proc.perm_table[0].processRights();
                    sender_proc.had_self_fault_handler = self_rights.fault_handler;
                    var new_rights = self_rights;
                    new_rights.fault_handler = false;
                    sender_proc.perm_table[0].rights = @bitCast(new_rights);
                    sender_proc.syncUserView();
                    sender_proc.perm_lock.unlock();
                    sender_proc._gen_lock.unlock();

                    // Link sender into target's fault_handler_targets list
                    // so target's death can revert sender to self-handling.
                    // If target died in the window between our writes above
                    // and now, its cleanupPhase1 has already walked an empty
                    // list and will never unlink us. Roll back the transfer:
                    // restore sender's slot-0 fault_handler bit and clear
                    // fault_handler_proc so sender goes back to self-handling.
                    if (!target_proc.linkFaultHandlerTarget(sender_proc)) {
                        sender_proc._gen_lock.lock();
                        sender_proc.fault_handler_proc = null;
                        sender_proc.perm_lock.lock();
                        const r = sender_proc.perm_table[0].processRights();
                        var rr = r;
                        rr.fault_handler = true;
                        sender_proc.perm_table[0].rights = @bitCast(rr);
                        sender_proc.syncUserView();
                        sender_proc.perm_lock.unlock();
                        sender_proc._gen_lock.unlock();
                        return E_INVAL;
                    }

                    // Check if target already has a handle to sender, add fault_handler bit
                    target_proc.perm_lock.lock();
                    var found_existing = false;
                    for (&target_proc.perm_table) |*slot| {
                        if (slot.object == .process and slot.object.process.ptr == proc_ptr) {
                            var existing_rights: ProcessHandleRights = @bitCast(slot.rights);
                            existing_rights.fault_handler = true;
                            slot.rights = @bitCast(existing_rights);
                            found_existing = true;
                            break;
                        }
                    }
                    target_proc.perm_lock.unlock();

                    if (!found_existing) {
                        _ = target_proc.insertPerm(.{
                            .handle = 0,
                            .object = .{ .process = process_mod.slabRefNow(Process, proc_ptr) },
                            .rights = granted_u16,
                        }) catch {
                            // Rollback the partially committed fault_handler
                            // transfer in reverse order of commit. Without
                            // this, the sender is left with
                            // `fault_handler_proc = target_proc` and a cleared
                            // slot-0 bit, linked into target's
                            // fault_handler_targets list — but no handle to
                            // the sender exists in target. Subsequent faults
                            // would route to target with no way for target to
                            // receive them, and releaseFaultHandler on target
                            // death would restore the slot-0 bit using
                            // had_self_fault_handler while target never had
                            // the relationship reflected in its perm table.

                            // 1. Unlink sender from target's fault_handler_targets list.
                            target_proc.unlinkFaultHandlerTarget(sender_proc);

                            // 2. Restore sender's slot-0 fault_handler bit and
                            //    clear fault_handler_proc, reverting to
                            //    self-handling. Ordering mirrors the
                            //    linkFaultHandlerTarget-failure rollback
                            //    above: under sender_proc.lock nested with
                            //    perm_lock.
                            sender_proc._gen_lock.lock();
                            sender_proc.fault_handler_proc = null;
                            sender_proc.perm_lock.lock();
                            var rb_rights = sender_proc.perm_table[0].processRights();
                            // Only restore the bit if the sender originally
                            // had it — mirrors releaseFaultHandler semantics
                            // so we don't synthesize a right that wasn't held
                            // at the moment of transfer. Bug A's check above
                            // ensures had_self_fault_handler was true when we
                            // reach this path, but we stay consistent with
                            // the released-handler invariant.
                            if (sender_proc.had_self_fault_handler) {
                                rb_rights.fault_handler = true;
                                sender_proc.perm_table[0].rights = @bitCast(rb_rights);
                                sender_proc.syncUserView();
                            }
                            sender_proc.perm_lock.unlock();
                            sender_proc._gen_lock.unlock();
                            return E_MAXCAP;
                        };
                    }

                    // Snapshot the sender's thread list under sender_proc.lock,
                    // then release the lock before walking it (insertThreadHandle
                    // takes target_proc.perm_lock and we don't want to nest).
                    sender_proc._gen_lock.lock();
                    const num_threads = sender_proc.num_threads;
                    var threads_copy: [Process.MAX_THREADS]*Thread = undefined;
                    @memcpy(threads_copy[0..num_threads], sender_proc.threads[0..num_threads]);
                    sender_proc._gen_lock.unlock();

                    for (threads_copy[0..num_threads]) |t| {
                        _ = target_proc.insertThreadHandle(t, ThreadHandleRights.full) catch {};
                    }

                    target_proc.syncUserView();
                    return E_OK;
                }

                // Normal HANDLE_SELF transfer (no fault_handler)
                const new_entry = PermissionEntry{
                    .handle = 0,
                    .object = .{ .process = process_mod.slabRefNow(Process, proc_ptr) },
                    .rights = granted_u16,
                };
                _ = target_proc.insertPerm(new_entry) catch {
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
                .object = .{ .process = process_mod.slabRefNow(Process, proc_ptr) },
                .rights = granted_u16,
            };
            sender_proc.perm_lock.unlock();
            _ = target_proc.insertPerm(new_entry) catch {
                return E_MAXCAP;
            };
            return E_OK;
        },
        .device_region => |dev_ref| {
            const device = dev_ref.ptr;
            sender_proc.perm_lock.unlock();
            if (!src_entry.deviceRights().grant) return E_PERM;
            const granted_u16: u16 = @truncate(rights_val);
            if (!isSubset(granted_u16, src_entry.rights)) return E_PERM;
            // Device transfer is parent->child only. Identity-compare
            // target's parent SlabRef against sender; absence or mismatch
            // both fail.
            const parent_matches = if (target_proc.parent) |pref| pref.ptr == sender_proc else false;
            if (!parent_matches) return E_PERM;
            const target_self = target_proc.getPermByHandle(0) orelse return E_PERM;
            if (!target_self.processRights().device_own) return E_PERM;
            const new_entry = PermissionEntry{
                .handle = 0,
                .object = .{ .device_region = process_mod.slabRefNow(DeviceRegion, device) },
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
    const payload_regs = arch.syscall.getIpcPayloadWords(ctx);
    if (word_count < 2) return .{ .handle = 0, .rights = 0 };
    return .{
        .handle = payload_regs[word_count - 2],
        .rights = payload_regs[word_count - 1],
    };
}

fn validateIpcSendRights(entry: PermissionEntry, meta: IpcMetadata, sender_proc: *Process, src_ctx: *const ArchCpuContext) i64 {
    // Red-team Finding (5c80fe4): block cap_transfer self-sends as a
    // second line of defense after the target_proc == sender_proc check
    // in transferCapability. The slot-0 entry stores ProcessRights, not
    // ProcessHandleRights, and reinterpreting the layout lets
    // ProcessRights.spawn_thread (bit 0) masquerade as send_words,
    // passing this gate without holding any send_* right.
    const self_send = entry.object == .process and entry.object.process.ptr == sender_proc;
    if (self_send and meta.cap_transfer) return E_INVAL;
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
    thread.state = .ready;
    const target_core = if (thread.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
    sched.enqueueOnCore(target_core, thread);
}

pub fn sysIpcSend(ctx: *ArchCpuContext) SyscallResult {
    kprof.enter(.sys_ipc_send);
    defer kprof.exit(.sys_ipc_send);
    const thread = sched.currentThread().?;
    // self-alive: currentThread() is dispatched on this core; its
    // owning Process is alive across the syscall.
    const proc = thread.process.ptr;
    const target_handle = arch.syscall.getIpcHandle(ctx);
    const meta = parseIpcMetadata(arch.syscall.getIpcMetadata(ctx));

    // Look up target process
    const target_entry = proc.getPermByHandle(target_handle) orelse return .{ .ret = E_BADCAP };
    if (target_entry.object != .process) return .{ .ret = E_BADCAP };
    const target_proc = target_entry.object.process.ptr;

    // §2.6.30: lazily convert dead process entries on IPC attempt.
    target_proc._gen_lock.lock();
    const target_alive = target_proc.alive;
    target_proc._gen_lock.unlock();
    if (!target_alive) {
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
    const saved_return = arch.syscall.getSyscallReturn(receiver.ctx);
    const saved_meta = arch.syscall.getIpcMetadata(receiver.ctx);
    const saved_payload = arch.syscall.saveIpcPayload(receiver.ctx);
    // On aarch64, x0 serves as both the syscall return register and the
    // first IPC payload word. setSyscallReturn must precede copyIpcPayload
    // so that when word_count >= 1, copyIpcPayload's write of x0 wins and
    // carries the true reply word 0. On x86_64 rax and rdi are independent,
    // so the order is immaterial there.
    arch.syscall.setSyscallReturn(receiver.ctx, @bitCast(E_OK));
    arch.syscall.copyIpcPayload(receiver.ctx, ctx, meta.word_count);
    // Set recv metadata: bit 0 = 0 (from send), bits [3:1] = word_count
    arch.syscall.setIpcMetadata(receiver.ctx, @as(u64, meta.word_count) << 1);

    // Handle capability transfer
    if (meta.cap_transfer) {
        const cap = getCapPayload(ctx, meta.word_count);
        const cap_result = transferCapability(proc, target_proc, cap.handle, cap.rights);
        if (cap_result != E_OK) {
            // Roll back: restore receiver ctx and re-block.
            arch.syscall.setSyscallReturn(receiver.ctx, saved_return);
            arch.syscall.setIpcMetadata(receiver.ctx, saved_meta);
            arch.syscall.restoreIpcPayload(receiver.ctx, saved_payload);
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
    kprof.enter(.sys_ipc_call);
    defer kprof.exit(.sys_ipc_call);
    const thread = sched.currentThread().?;
    // self-alive: currentThread() is dispatched on this core; its
    // owning Process is alive across the syscall.
    const proc = thread.process.ptr;
    const target_handle = arch.syscall.getIpcHandle(ctx);
    const meta = parseIpcMetadata(arch.syscall.getIpcMetadata(ctx));

    const target_entry = proc.getPermByHandle(target_handle) orelse return .{ .ret = E_BADCAP };
    if (target_entry.object != .process) return .{ .ret = E_BADCAP };
    const target_proc = target_entry.object.process.ptr;

    // §2.6.30: lazily convert dead process entries on IPC attempt.
    target_proc._gen_lock.lock();
    const target_alive = target_proc.alive;
    target_proc._gen_lock.unlock();
    if (!target_alive) {
        proc.convertToDeadProcess(target_proc);
        return .{ .ret = E_BADCAP };
    }

    const rights_check = validateIpcSendRights(target_entry, meta, proc, ctx);
    if (rights_check != E_OK) return .{ .ret = rights_check };

    target_proc.msg_box.lock.lock();

    if (target_proc.msg_box.isReceiving()) {
        // Receiver is waiting — deliver and queue caller for reply.
        const receiver = target_proc.msg_box.takeReceiverLocked();
        const saved_return = arch.syscall.getSyscallReturn(receiver.ctx);
        const saved_meta = arch.syscall.getIpcMetadata(receiver.ctx);
        const saved_payload = arch.syscall.saveIpcPayload(receiver.ctx);
        // Order: setSyscallReturn before copyIpcPayload (see comment on the
        // sysIpcSend path above — x0 is shared on aarch64).
        arch.syscall.setSyscallReturn(receiver.ctx, @bitCast(E_OK));
        arch.syscall.copyIpcPayload(receiver.ctx, ctx, meta.word_count);
        arch.syscall.setIpcMetadata(receiver.ctx, (@as(u64, meta.word_count) << 1) | 1); // bit 0 = 1 (from call)

        if (meta.cap_transfer) {
            const cap = getCapPayload(ctx, meta.word_count);
            const cap_result = transferCapability(proc, target_proc, cap.handle, cap.rights);
            if (cap_result != E_OK) {
                // Roll back: restore receiver ctx and re-block.
                arch.syscall.setSyscallReturn(receiver.ctx, saved_return);
                arch.syscall.setIpcMetadata(receiver.ctx, saved_meta);
                arch.syscall.restoreIpcPayload(receiver.ctx, saved_payload);
                target_proc.msg_box.beginReceivingLocked(receiver);
                target_proc.msg_box.lock.unlock();
                return .{ .ret = cap_result };
            }
        }

        target_proc.msg_box.beginPendingReplyLocked(thread);
        thread.ipc_server = SlabRef(Process).init(target_proc, target_proc._gen_lock.currentGen());
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
        thread.ipc_server = SlabRef(Process).init(target_proc, target_proc._gen_lock.currentGen());
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
    kprof.enter(.sys_ipc_recv);
    defer kprof.exit(.sys_ipc_recv);
    const thread = sched.currentThread().?;
    // self-alive: currentThread() on this core.
    const proc = thread.process.ptr;
    const blocking = (arch.syscall.getIpcMetadata(ctx) & 0x2) != 0;

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
    const waiter_meta = parseIpcMetadata(arch.syscall.getIpcMetadata(waiter.ctx));
    arch.syscall.copyIpcPayload(ctx, waiter.ctx, waiter_meta.word_count);

    // Set recv metadata: bit 0 = 1 (always from call — send doesn't queue).
    arch.syscall.setIpcMetadata(ctx, (@as(u64, waiter_meta.word_count) << 1) | 1);

    // Handle capability transfer.
    if (waiter_meta.cap_transfer) {
        const cap = getCapPayload(waiter.ctx, waiter_meta.word_count);
        // self-alive: `waiter` is the dequeued sender we are now
        // servicing; its owning Process is still alive while the
        // thread is in the rendezvous.
        const cap_result = transferCapability(waiter.process.ptr, proc, cap.handle, cap.rights);
        if (cap_result != E_OK) {
            // Put waiter back at head of the queue.
            proc.msg_box.enqueueFrontLocked(waiter);
            proc.msg_box.lock.unlock();
            return .{ .ret = cap_result };
        }
    }

    proc.msg_box.beginPendingReplyLocked(waiter);
    proc.msg_box.lock.unlock();

    // aarch64: copyIpcPayload already wrote the true reply word 0 into x0
    // when word_count >= 1. Tell the arch dispatcher not to overwrite it
    // with the E_OK return. On x86_64 ret goes into rax (separate from
    // rdi/reply word 0), so the flag is a harmless no-op there.
    if (waiter_meta.word_count >= 1) {
        return .{ .ret = E_OK, .skip_ret_write = true };
    }
    return .{ .ret = E_OK };
}

pub fn sysIpcReply(ctx: *ArchCpuContext) SyscallResult {
    kprof.enter(.sys_ipc_reply);
    defer kprof.exit(.sys_ipc_reply);
    const thread = sched.currentThread().?;
    // self-alive: currentThread() on this core.
    const proc = thread.process.ptr;
    const reply_meta = arch.syscall.getIpcMetadata(ctx);
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
            // self-alive: `pc` is the msg_box's pending caller,
            // still referenced by the box until we unblock it; its
            // owning Process is alive across the reply.
            reply_cap_err = transferCapability(proc, pc.process.ptr, cap.handle, cap.rights);
        }
        if (reply_cap_err != E_OK) {
            arch.syscall.setSyscallReturn(pc.ctx, @bitCast(reply_cap_err));
        } else {
            // Order: setSyscallReturn before copyIpcPayload on aarch64 (x0
            // is shared between return value and reply word 0). See
            // sysIpcSend's matching comment for rationale.
            arch.syscall.setSyscallReturn(pc.ctx, @bitCast(E_OK));
            arch.syscall.copyIpcPayload(pc.ctx, ctx, reply_word_count);
            arch.syscall.setIpcMetadata(pc.ctx, (@as(u64, reply_word_count) << 1) | 1);
        }

        pc.ipc_server = null;
    }

    if (atomic_recv) {
        // Reply + recv atomically.
        if (proc.msg_box.dequeueLocked()) |waiter| {
            const waiter_meta = parseIpcMetadata(arch.syscall.getIpcMetadata(waiter.ctx));

            // Capability transfer runs before we deliver to the receiver:
            // on failure, put the waiter back at the head of the queue
            // and return E_MAXCAP (§2.11.14) — mirrors sysIpcRecv.
            if (waiter_meta.cap_transfer) {
                const cap = getCapPayload(waiter.ctx, waiter_meta.word_count);
                // self-alive: `waiter` is the dequeued sender; its
                // owning Process is alive while the thread is in
                // the rendezvous.
                const cap_result = transferCapability(waiter.process.ptr, proc, cap.handle, cap.rights);
                if (cap_result != E_OK) {
                    proc.msg_box.enqueueFrontLocked(waiter);
                    proc.msg_box.lock.unlock();
                    if (caller_thread) |ct| wakeThread(ct);
                    return .{ .ret = cap_result };
                }
            }

            // Order: setSyscallReturn before copyIpcPayload on aarch64 (x0
            // is shared between return value and reply word 0). See
            // sysIpcSend's matching comment for rationale.
            arch.syscall.setSyscallReturn(ctx, @bitCast(E_OK));
            arch.syscall.copyIpcPayload(ctx, waiter.ctx, waiter_meta.word_count);
            arch.syscall.setIpcMetadata(ctx, (@as(u64, waiter_meta.word_count) << 1) | 1);

            proc.msg_box.beginPendingReplyLocked(waiter);
            proc.msg_box.lock.unlock();

            if (caller_thread) |ct| wakeThread(ct);
            // aarch64: preserve the reply word 0 we just wrote to x0 when
            // no error is being returned. See sysIpcRecv for the same
            // pattern.
            if (reply_cap_err == E_OK and waiter_meta.word_count >= 1) {
                return .{ .ret = E_OK, .skip_ret_write = true };
            }
            return .{ .ret = if (reply_cap_err != E_OK) reply_cap_err else E_OK };
        } else if (recv_blocking) {
            proc.msg_box.beginReceivingLocked(thread);
            proc.msg_box.lock.unlock();

            // TODO: same direct-switch hang issue as above; use wakeThread
            // for now and block self via switchToNextReady.
            if (caller_thread) |ct| wakeThread(ct);
            thread.state = .blocked;
            arch.syscall.setSyscallReturn(ctx, @bitCast(reply_cap_err));
            thread.ctx = ctx;
            thread.on_cpu.store(false, .release);
            sched.switchToNextReady();
            unreachable;
        } else {
            proc.msg_box.lock.unlock();
            if (caller_thread) |ct| wakeThread(ct);
            const recv_err = if (reply_cap_err != E_OK) reply_cap_err else E_AGAIN;
            arch.syscall.setSyscallReturn(ctx, @bitCast(recv_err));
            return .{ .ret = recv_err };
        }
    } else {
        proc.msg_box.lock.unlock();

        if (caller_thread == null) return .{ .ret = reply_cap_err };

        const ct = caller_thread.?;
        thread.state = .ready;
        arch.syscall.setSyscallReturn(ctx, @bitCast(reply_cap_err));
        const result = sched.switchToThread(thread, ct, ctx, true);
        if (result != 0) {
            thread.state = .running;
            wakeThread(ct);
            return .{ .ret = reply_cap_err };
        }
        unreachable;
    }
}

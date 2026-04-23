const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const futex = zag.proc.futex;
const kprof = zag.kprof.trace_id;
const paging = zag.memory.paging;
const process_mod = zag.proc.process;
const sched = zag.sched.scheduler;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;
const Process = zag.proc.process.Process;
const SyscallResult = zag.syscall.dispatch.SyscallResult;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;

const E_AGAIN = errors.E_AGAIN;
const E_BADADDR = errors.E_BADADDR;
const E_BADCAP = errors.E_BADCAP;
const E_BUSY = errors.E_BUSY;
const E_INVAL = errors.E_INVAL;
const E_NOENT = errors.E_NOENT;
const E_OK = errors.E_OK;
const E_PERM = errors.E_PERM;

/// FaultMessage userspace layout (arch.cpu.fault_msg_size bytes). Stable wire
/// format shared with libz.FaultMessage:
///   0   process_handle: u64    handle ID of source process in handler's table
///   8   thread_handle:  u64    handle ID of faulting thread in handler's table
///   16  fault_reason:   u8     FaultReason enum value
///   17  _pad:           [7]u8
///   24  fault_addr:     u64    fault VA (CR2 on x86, FAR_EL1 on aarch64)
///   32  ip:             u64    instruction pointer at fault
///   40  flags:          u64    flags register (RFLAGS / SPSR_EL1)
///   48  sp:             u64    stack pointer
///   56  gprs:           N×u64  GPR snapshot (15 on x86-64, 31 on aarch64)
const fault_msg_size = arch.cpu.fault_msg_size;
const fault_regs_size = arch.cpu.fault_regs_size;

/// Build a FaultMessage in a temporary kernel buffer.
fn buildFaultMessage(process_handle: u64, thread_handle: u64, faulted: *Thread) [fault_msg_size]u8 {
    var buf: [fault_msg_size]u8 = undefined;
    @as(*align(1) u64, @ptrCast(&buf[0])).* = process_handle;
    @as(*align(1) u64, @ptrCast(&buf[8])).* = thread_handle;
    buf[16] = @intFromEnum(faulted.fault_reason);
    @memset(buf[17..24], 0);
    @as(*align(1) u64, @ptrCast(&buf[24])).* = faulted.fault_addr;
    // Serialize from the user fault frame (the same frame a subsequent
    // FAULT_RESUME_MODIFIED will write through) rather than `faulted.ctx`,
    // which on aarch64 points at the nested SGI frame from `yield()`.
    const regs_src = faulted.fault_user_ctx orelse faulted.ctx;
    const snap = arch.cpu.serializeFaultRegs(regs_src);
    @as(*align(1) u64, @ptrCast(&buf[32])).* = snap.ip;
    @as(*align(1) u64, @ptrCast(&buf[40])).* = snap.flags;
    @as(*align(1) u64, @ptrCast(&buf[48])).* = snap.sp;
    var off: usize = 56;
    for (snap.gprs) |v| {
        @as(*align(1) u64, @ptrCast(&buf[off])).* = v;
        off += 8;
    }
    return buf;
}

/// Write a FaultMessage from the current address space directly into the
/// caller's user buffer (used on the synchronous-dequeue path where the
/// receiver is the current thread). Copies via physmap to avoid faulting
/// the kernel on a demand-paged user VA (interrupts.zig kills ring-0 user
/// faults outright).
fn writeFaultMessage(proc: *Process, buf_ptr: u64, process_handle: u64, thread_handle: u64, faulted: *Thread) void {
    const msg = buildFaultMessage(process_handle, thread_handle, faulted);
    // Pre-fault every destination page, then copy through physmap.
    var remaining: usize = fault_msg_size;
    var src_off: usize = 0;
    var dst_va: u64 = buf_ptr;
    while (remaining > 0) {
        const page_off = dst_va & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_off);
        // Force the page in via demand-page if not already committed.
        // Ignore NoMapping / PermissionDenied — faultRecvValidateBuf already
        // checked the VMM nodes and write rights; an error here is a
        // shared/MMIO node, which we simply skip (matching the pre-fix
        // behavior of silently writing into wrong memory).
        proc.vmm.demandPage(VAddr.fromInt(dst_va), true, false) catch {};
        if (arch.paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va))) |page_paddr| {
            const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
            const dst: [*]u8 = @ptrFromInt(physmap_addr);
            @memcpy(dst[0..chunk], msg[src_off..][0..chunk]);
        }
        src_off += chunk;
        dst_va += chunk;
        remaining -= chunk;
    }
}

/// Look up the handle IDs for a faulted source thread in the handler's
/// perm table. Returns (process_handle, thread_handle); zero values mean
/// "not found in table" (which can happen if the source process is the
/// handler itself, in which case process_handle = HANDLE_SELF = 0).
fn lookupFaultHandles(handler: *Process, faulted: *Thread) struct { proc_h: u64, thread_h: u64 } {
    handler.perm_lock.lock();
    defer handler.perm_lock.unlock();
    var proc_h: u64 = 0;
    var thread_h: u64 = 0;
    for (&handler.perm_table) |*slot| {
        switch (slot.object) {
            .thread => |t| if (t == faulted) {
                thread_h = slot.handle;
            },
            .process => |p| if (p == faulted.process) {
                proc_h = slot.handle;
            },
            else => {},
        }
    }
    return .{ .proc_h = proc_h, .thread_h = thread_h };
}

fn faultHandlerCheck(proc: *Process) bool {
    proc.perm_lock.lock();
    defer proc.perm_lock.unlock();
    if (proc.perm_table[0].processRights().fault_handler) return true;
    for (proc.perm_table[1..]) |slot| {
        if (slot.object == .process and slot.processHandleRights().fault_handler) return true;
    }
    return false;
}

fn faultRecvValidateBuf(proc: *Process, buf_ptr: u64) i64 {
    if (!address.AddrSpacePartition.user.contains(buf_ptr)) return E_BADADDR;
    const buf_end = std.math.add(u64, buf_ptr, fault_msg_size) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(buf_end -| 1)) return E_BADADDR;
    var check_addr = buf_ptr;
    while (check_addr < buf_end) {
        const node = proc.vmm.findNode(VAddr.fromInt(check_addr)) orelse return E_BADADDR;
        node._gen_lock.lock();
        const writable = node.rights.write;
        const node_end = node.end();
        node._gen_lock.unlock();
        if (!writable) return E_BADADDR;
        check_addr = node_end;
    }
    return E_OK;
}

pub fn sysFaultRecv(ctx: *ArchCpuContext, buf_ptr: u64, blocking: u64) SyscallResult {
    kprof.enter(.sys_fault_recv);
    defer kprof.exit(.sys_fault_recv);
    const thread = sched.currentThread().?;
    const proc = thread.process;

    if (!faultHandlerCheck(proc)) return .{ .ret = E_PERM };

    const buf_check = faultRecvValidateBuf(proc, buf_ptr);
    if (buf_check != E_OK) return .{ .ret = buf_check };

    while (true) {
        proc.fault_box.lock.lock();

        if (proc.fault_box.isPendingReply()) {
            proc.fault_box.lock.unlock();
            return .{ .ret = E_BUSY };
        }

        if (proc.fault_box.dequeueLocked()) |faulted| {
            proc.fault_box.beginPendingReplyLocked(faulted);
            proc.fault_box.lock.unlock();

            const handles = lookupFaultHandles(proc, faulted);
            writeFaultMessage(proc, buf_ptr, handles.proc_h, handles.thread_h, faulted);
            return .{ .ret = @intCast(handles.thread_h) };
        }

        if (blocking == 0) {
            proc.fault_box.lock.unlock();
            return .{ .ret = E_AGAIN };
        }

        // Block on recv. The faultBlock path will wake us when a fault
        // is enqueued; we then loop and re-attempt the dequeue in our
        // own address space.
        proc.fault_box.beginReceivingLocked(thread);
        proc.fault_box.lock.unlock();

        thread.state = .blocked;
        thread.ctx = ctx;
        thread.on_cpu.store(false, .release);
        sched.switchToNextReady();
        // Never returns from switchToNextReady on this stack — when we're
        // re-dispatched the int 0x80 frame is restored and execution
        // resumes from the syscall epilogue. The loop here is technically
        // unreachable on this code path, but it's also harmless and makes
        // the contract obvious to the reader.
        unreachable;
    }
}

/// Read fault_regs_size bytes of FaultMessage saved-regs (ip + flags + sp +
/// GPRs) from `src_ptr` and apply them to the FAULTING thread's user frame.
///
/// `dst.ctx` is the kernel-mode context captured when the thread yielded
/// out of `faultBlock` — writing to it has no effect on the user-mode
/// resume because the kernel unwinds back through the original page fault
/// frame, which is what iret reads. The original user-mode iret frame is
/// stashed on `dst.fault_user_ctx` by `faultBlock` so we can target it
/// here.
fn applyModifiedRegs(dst: *Thread, src_ptr: u64) void {
    const target = dst.fault_user_ctx orelse return;
    const buf: [*]const u8 = @ptrFromInt(src_ptr);
    arch.cpu.userAccessBegin();
    var snapshot: arch.cpu.FaultRegSnapshot = undefined;
    snapshot.ip = @as(*align(1) const u64, @ptrCast(buf + 0)).*;
    snapshot.flags = @as(*align(1) const u64, @ptrCast(buf + 8)).*;
    snapshot.sp = @as(*align(1) const u64, @ptrCast(buf + 16)).*;
    var off: usize = 24;
    for (&snapshot.gprs) |*gpr| {
        gpr.* = @as(*align(1) const u64, @ptrCast(buf + off)).*;
        off += 8;
    }
    arch.cpu.userAccessEnd();
    arch.cpu.applyFaultRegs(target, snapshot);
}

const fault_kill: u64 = 0;
const fault_resume: u64 = 1;
const fault_resume_modified: u64 = 2;
const fault_exclude_next: u64 = 0x1;
const fault_exclude_permanent: u64 = 0x2;

pub fn sysFaultReply(ctx: *ArchCpuContext, fault_token: u64, action: u64, modified_regs_ptr: u64) i64 {
    kprof.enter(.sys_fault_reply);
    defer kprof.exit(.sys_fault_reply);
    if (action > fault_resume_modified) return E_INVAL;

    const proc = sched.currentProc();
    const flags = arch.syscall.getIpcMetadata(ctx);

    // §2.12.22: both exclude bits set is invalid.
    if ((flags & fault_exclude_next) != 0 and (flags & fault_exclude_permanent) != 0) {
        return E_INVAL;
    }

    // §4.34.6: validate modified_regs_ptr for RESUME_MODIFIED.
    //
    // The 144-byte register buffer can straddle a VMM-node boundary.
    // `findNode` returns the node containing the first byte only, so
    // walk every 4 KiB page the buffer covers and verify each one is
    // backed by a readable node. Without this, `applyModifiedRegs`
    // dereferences the tail bytes directly under userAccessBegin,
    // and an unmapped / non-readable tail page faults the kernel.
    if (action == fault_resume_modified) {
        if (!address.AddrSpacePartition.user.contains(modified_regs_ptr)) return E_BADADDR;
        const buf_end = std.math.add(u64, modified_regs_ptr, fault_regs_size) catch return E_BADADDR;
        if (buf_end == modified_regs_ptr) return E_BADADDR;
        if (!address.AddrSpacePartition.user.contains(buf_end - 1)) return E_BADADDR;
        const first_page = std.mem.alignBackward(u64, modified_regs_ptr, paging.PAGE4K);
        const last_page = std.mem.alignBackward(u64, buf_end - 1, paging.PAGE4K);
        var page = first_page;
        while (true) {
            const node = proc.vmm.findNode(VAddr.fromInt(page)) orelse return E_BADADDR;
            node._gen_lock.lock();
            const readable = node.rights.read;
            node._gen_lock.unlock();
            if (!readable) return E_BADADDR;
            if (page == last_page) break;
            page += paging.PAGE4K;
        }
    }

    proc.fault_box.lock.lock();

    if (!proc.fault_box.isPendingReply()) {
        proc.fault_box.lock.unlock();
        return E_INVAL;
    }

    const pending = proc.fault_box.pending_thread orelse {
        // pending_reply with null pending_thread shouldn't happen for fault box.
        _ = proc.fault_box.endPendingReplyLocked();
        proc.fault_box.lock.unlock();
        return E_INVAL;
    };

    // Validate the token matches the pending thread's handle in our perm
    // table. If the source thread was killed externally between fault_recv
    // and fault_reply, the handle was cleared, so the lookup returns 0 —
    // distinct from any valid token.
    const pending_handle = proc.findThreadHandle(pending) orelse {
        _ = proc.fault_box.endPendingReplyLocked();
        proc.fault_box.lock.unlock();
        return E_NOENT;
    };
    if (pending_handle != fault_token) {
        proc.fault_box.lock.unlock();
        return E_NOENT;
    }

    _ = proc.fault_box.endPendingReplyLocked();
    proc.fault_box.lock.unlock();

    // Apply FAULT_EXCLUDE_* flags to the pending thread's perm entry.
    if ((flags & (fault_exclude_next | fault_exclude_permanent)) != 0) {
        proc.perm_lock.lock();
        for (&proc.perm_table) |*slot| {
            if (slot.object == .thread and slot.object.thread == pending) {
                if ((flags & fault_exclude_next) != 0) {
                    slot.exclude_oneshot = true;
                    slot.exclude_permanent = false;
                } else {
                    slot.exclude_oneshot = false;
                    slot.exclude_permanent = true;
                }
                break;
            }
        }
        proc.syncUserView();
        proc.perm_lock.unlock();
    }

    const src = pending.process;

    // §2.12.23: on ANY fault_reply, release all .suspended siblings before
    // applying the action on the faulting thread.
    src._gen_lock.lock();
    {
        var i: u64 = 0;
        while (i < src.num_threads) {
            const t = src.threads[i];
            if (t.state == .suspended) {
                t.state = .ready;
            }
            i += 1;
        }
    }
    const sib_mask = src.suspended_thread_slots;
    src.suspended_thread_slots = 0;
    src._gen_lock.unlock();

    {
        var i: u64 = 0;
        while (i < src.num_threads) {
            const t = src.threads[i];
            if ((sib_mask & (@as(u64, 1) << @intCast(t.slot_index))) != 0) {
                const target_core = if (t.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
                sched.enqueueOnCore(target_core, t);
            }
            i += 1;
        }
    }

    switch (action) {
        fault_kill => {
            // §2.12.24: kill ONLY the faulting thread. If it is the last
            // non-exited thread, Thread.deinit -> lastThreadExited drives
            // process exit/restart per §2.6.
            src._gen_lock.lock();
            pending.state = .exited;
            const faulted_bit = @as(u64, 1) << @intCast(pending.slot_index);
            src.faulted_thread_slots &= ~faulted_bit;
            src._gen_lock.unlock();

            while (pending.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            sched.removeFromAnyRunQueue(pending);
            if (pending.futex_paddr.addr != 0) {
                futex.removeBlockedThread(pending);
            }
            if (pending.ipc_server) |server| {
                server.msg_box.lock.lock();
                if (server.msg_box.isPendingReply() and server.msg_box.pending_thread == pending) {
                    _ = server.msg_box.endPendingReplyLocked();
                } else {
                    _ = server.msg_box.removeLocked(pending);
                }
                pending.ipc_server = null;
                server.msg_box.lock.unlock();
            }
            // Scrub any residual entries for `pending` from our own
            // fault_box (the handler's box). endPendingReplyLocked above
            // cleared the pending_reply slot, but a re-enqueued or queued
            // entry could remain if the thread was handled in a nested
            // context. Mirror what target.fault_box / msg_box scrubbing
            // does in the intra-process case.
            process_mod.scrubFromFaultBoxPub(&proc.fault_box, pending);
            pending.deinit();
        },
        fault_resume, fault_resume_modified => {
            if (action == fault_resume_modified) {
                applyModifiedRegs(pending, modified_regs_ptr);
            }
            // Clear the user iret frame pointer — the unwind path is about
            // to consume it via iret. Leaving a stale pointer would target
            // a previous frame on the next fault.
            pending.fault_user_ctx = null;
            src._gen_lock.lock();
            pending.state = .ready;
            const faulted_bit = @as(u64, 1) << @intCast(pending.slot_index);
            src.faulted_thread_slots &= ~faulted_bit;
            src._gen_lock.unlock();

            const target_core = if (pending.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
            sched.enqueueOnCore(target_core, pending);
        },
        else => unreachable,
    }

    return E_OK;
}

pub fn sysFaultReadMem(proc_handle: u64, vaddr: u64, buf_ptr: u64, len: u64) i64 {
    const proc = sched.currentProc();
    if (proc_handle == 0) return E_PERM;
    const entry = proc.getPermByHandle(proc_handle) orelse return E_BADCAP;
    if (entry.object != .process) return E_BADCAP;
    if (!entry.processHandleRights().fault_handler) return E_PERM;

    if (len == 0) return E_INVAL;

    const target = entry.object.process;

    // Validate target vaddr is within user address space
    if (!address.AddrSpacePartition.user.contains(vaddr)) return E_BADADDR;
    const vaddr_end = std.math.add(u64, vaddr, len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(vaddr_end -| 1)) return E_BADADDR;

    // Validate caller's buffer is writable
    if (!address.AddrSpacePartition.user.contains(buf_ptr)) return E_BADADDR;
    const buf_end = std.math.add(u64, buf_ptr, len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(buf_end -| 1)) return E_BADADDR;

    target._gen_lock.lock();
    defer target._gen_lock.unlock();

    // Read from target process's virtual address space via physmap.
    // Pre-fault both sides: demand-page the target page so debuggers can
    // read uncommitted-yet-reserved pages, and demand-page the caller's
    // destination so a ring-0 @memcpy doesn't take a user fault.
    var remaining = len;
    var src_addr = vaddr;
    var dst_addr = buf_ptr;
    while (remaining > 0) {
        const page_offset = src_addr & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_offset);
        target.vmm.demandPage(VAddr.fromInt(src_addr), false, false) catch {};
        proc.vmm.demandPage(VAddr.fromInt(dst_addr), true, false) catch {};
        const src_paddr = arch.paging.resolveVaddr(target.addr_space_root, VAddr.fromInt(src_addr)) orelse return E_BADADDR;
        const dst_paddr = arch.paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_addr)) orelse return E_BADADDR;
        const src_phys = VAddr.fromPAddr(src_paddr, null).addr + page_offset;
        const dst_page_off = dst_addr & 0xFFF;
        const dst_phys = VAddr.fromPAddr(dst_paddr, null).addr + dst_page_off;
        const src: [*]const u8 = @ptrFromInt(src_phys);
        const dst: [*]u8 = @ptrFromInt(dst_phys);
        @memcpy(dst[0..chunk], src[0..chunk]);
        remaining -= chunk;
        src_addr += chunk;
        dst_addr += chunk;
    }

    return E_OK;
}

pub fn sysFaultWriteMem(proc_handle: u64, vaddr: u64, buf_ptr: u64, len: u64) i64 {
    const proc = sched.currentProc();
    if (proc_handle == 0) return E_PERM;
    const entry = proc.getPermByHandle(proc_handle) orelse return E_BADCAP;
    if (entry.object != .process) return E_BADCAP;
    if (!entry.processHandleRights().fault_handler) return E_PERM;

    if (len == 0) return E_INVAL;

    const target = entry.object.process;

    // Validate target vaddr is within user address space
    if (!address.AddrSpacePartition.user.contains(vaddr)) return E_BADADDR;
    const vaddr_end = std.math.add(u64, vaddr, len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(vaddr_end -| 1)) return E_BADADDR;

    // Validate caller's buffer is readable
    if (!address.AddrSpacePartition.user.contains(buf_ptr)) return E_BADADDR;
    const buf_end = std.math.add(u64, buf_ptr, len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(buf_end -| 1)) return E_BADADDR;

    target._gen_lock.lock();
    defer target._gen_lock.unlock();

    // Write to target process's virtual address space via physmap (bypasses page perms).
    // Pre-fault both sides: demand-page the target page (even uncommitted
    // pages within a reservation) and the caller's source buffer so
    // ring-0 @memcpy never takes a user fault.
    //
    // The fault handler may be patching the target's instruction stream
    // (debugger / spec §4.1.34 instruction patching). On aarch64 the I-D
    // caches are not coherent: after the data-side @memcpy lands in the
    // physmap view we must clean the just-written lines to the Point of
    // Unification AND invalidate the instruction cache, otherwise the
    // target re-faults at the same RIP fetching stale bytes. On x86-64
    // both helpers are no-ops (coherent I-cache).
    var remaining = len;
    var dst_addr = vaddr;
    var src_addr = buf_ptr;
    while (remaining > 0) {
        const page_offset = dst_addr & 0xFFF;
        const chunk = @min(remaining, paging.PAGE4K - page_offset);
        target.vmm.demandPage(VAddr.fromInt(dst_addr), true, false) catch {};
        proc.vmm.demandPage(VAddr.fromInt(src_addr), false, false) catch {};
        const page_paddr = arch.paging.resolveVaddr(target.addr_space_root, VAddr.fromInt(dst_addr)) orelse return E_BADADDR;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_offset;
        const src: [*]const u8 = @ptrFromInt(src_addr);
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        // `dst` is a kernel physmap address; only `src` is a raw user VA,
        // so the SMAP window only needs to cover the read side of the copy.
        arch.cpu.userAccessBegin();
        @memcpy(dst[0..chunk], src[0..chunk]);
        arch.cpu.userAccessEnd();
        // Push the just-written cache lines to PoU so a subsequent
        // I-cache invalidate makes them visible to instruction fetch.
        arch.cpu.cleanDcacheToPou(physmap_addr, chunk);
        remaining -= chunk;
        dst_addr += chunk;
        src_addr += chunk;
    }
    // Broadcast I-cache invalidate so the target core re-fetches the
    // patched bytes on the next fault-resume. ARM ARM B2.4.6.
    arch.cpu.syncInstructionCache();

    return E_OK;
}

pub fn sysFaultSetThreadMode(thread_handle: u64, mode: u64) i64 {
    if (mode > 2) return E_INVAL;

    const proc = sched.currentProc();
    const pinned = proc.acquireThreadRef(thread_handle) orelse return E_BADCAP;
    const target_thread = pinned.thread;
    defer target_thread.releaseRef();

    // Verify caller holds fault_handler for the thread's owning process.
    // Two valid cases (§2.12.32):
    //   1. External handler: target_proc.fault_handler_proc == proc
    //   2. Self-handling:    target_proc == proc AND proc's slot 0 has
    //                        the fault_handler ProcessRights bit set.
    target_thread._gen_lock.lock();
    const target_proc = target_thread.process;
    target_thread._gen_lock.unlock();
    target_proc._gen_lock.lock();
    const handler_ok = target_proc.fault_handler_proc == proc;
    target_proc._gen_lock.unlock();
    const is_self_handler = target_proc == proc and
        proc.perm_table[0].processRights().fault_handler;
    if (!handler_ok and !is_self_handler) return E_PERM;

    // Update exclude flags on the thread's perm entry in caller's table
    proc.perm_lock.lock();
    defer proc.perm_lock.unlock();
    for (&proc.perm_table) |*slot| {
        if (slot.object == .thread and slot.object.thread == target_thread) {
            switch (mode) {
                0 => { // stop_all
                    slot.exclude_oneshot = false;
                    slot.exclude_permanent = false;
                },
                1 => { // exclude_next
                    slot.exclude_oneshot = true;
                    slot.exclude_permanent = false;
                },
                2 => { // exclude_permanent
                    slot.exclude_oneshot = false;
                    slot.exclude_permanent = true;
                },
                else => unreachable,
            }
            proc.syncUserView();
            return E_OK;
        }
    }
    return E_BADCAP;
}

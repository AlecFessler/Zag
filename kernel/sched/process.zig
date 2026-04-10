const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const elf = std.elf;
const futex = zag.sched.futex;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const restart_context_mod = zag.sched.restart_context;
const sched = zag.sched.scheduler;
const thread_mod = zag.sched.thread;

const ArchCpuContext = zag.arch.interrupts.ArchCpuContext;
const FaultReason = zag.perms.permissions.FaultReason;
const CrashReason = FaultReason;
const DeadProcessInfo = zag.perms.permissions.DeadProcessInfo;
const DeviceRegion = zag.memory.device_region.DeviceRegion;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const MessageBox = zag.sched.message_box.MessageBox;
const PAddr = zag.memory.address.PAddr;
const KernelObject = zag.perms.permissions.KernelObject;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Priority = zag.sched.thread.Priority;
const ProcessRights = zag.perms.permissions.ProcessRights;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const RestartContext = zag.sched.restart_context.RestartContext;
const SharedMemory = zag.memory.shared.SharedMemory;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const SpinLock = zag.sched.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const UserViewEntry = zag.perms.permissions.UserViewEntry;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;

pub const DEFAULT_STACK_PAGES: u32 = 8;
pub const MAX_PERMS: usize = 128;
pub const MAX_DMA_MAPPINGS: usize = 16;
pub const HANDLE_SELF: u64 = 0;

pub const DmaMapping = struct {
    device: *DeviceRegion,
    shm: *SharedMemory,
    dma_base: u64,
    num_pages: u64,
    active: bool,
};

pub const ProcessAllocator = SlabAllocator(Process, false, 0, 64, true);

pub const Process = struct {
    pid: u64,
    parent: ?*Process,
    alive: bool,
    restart_context: ?*RestartContext,
    addr_space_root: PAddr,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]*Thread,
    num_threads: u64,
    children: [MAX_CHILDREN]*Process,
    num_children: u64,
    lock: SpinLock,
    perm_table: [MAX_PERMS]PermissionEntry,
    perm_count: u32,
    perm_lock: SpinLock,
    handle_counter: u64,
    perm_view_vaddr: VAddr,
    perm_view_phys: PAddr,
    dma_mappings: [MAX_DMA_MAPPINGS]DmaMapping,
    num_dma_mappings: u32,
    /// IPC message passing state machine — used by ipc_send/call/recv/reply.
    msg_box: MessageBox = .{},
    /// Fault delivery state machine — used by fault_recv/fault_reply. Same
    /// struct, separate instance, completely independent state.
    fault_box: MessageBox = .{},
    fault_reason: FaultReason,
    restart_count: u16,
    perm_view_gen: u64 = 0,
    handle_refcount: u32 = 0,
    cleanup_complete: bool = false,
    fault_handler_proc: ?*Process = null,
    faulted_thread_slots: u64 = 0,
    suspended_thread_slots: u64 = 0,
    thread_handle_rights: ThreadHandleRights = ThreadHandleRights.full,
    max_thread_priority: Priority = .normal,
    // Back-pointer list of processes whose fault_handler_proc == self.
    // Walked on handler death to revert targets to self-handling (§2.12.35).
    // Protected by self.lock.
    fault_handler_targets_head: ?*Process = null,
    // Intrusive next-pointer for fault_handler_targets list of OUR handler.
    fault_handler_targets_next: ?*Process = null,
    // Whether slot 0's fault_handler bit was set at the moment the
    // relationship was established. releaseFaultHandler uses this to
    // decide whether restoring the bit is semantically valid — we never
    // want to synthesize a right the sender didn't have to begin with.
    had_self_fault_handler: bool = true,

    pub const MAX_THREADS = 64;
    pub const MAX_CHILDREN = 64;

    fn initPermTable(self: *Process, self_rights: ProcessRights) void {
        for (&self.perm_table) |*entry| {
            entry.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
        }
        self.perm_table[0] = .{
            .handle = HANDLE_SELF,
            .object = .{ .process = self },
            .rights = @bitCast(self_rights),
        };
        self.perm_count = 1;
        self.syncUserView();
    }

    pub fn syncUserView(self: *Process) void {
        if (self.perm_view_phys.addr == 0) return;
        const view_ptr: *[MAX_PERMS]UserViewEntry = @ptrFromInt(
            VAddr.fromPAddr(self.perm_view_phys, null).addr,
        );
        // Bump generation counter before syncing entries
        self.perm_view_gen += 1;
        for (&self.perm_table, 0..) |*entry, i| {
            view_ptr[i] = UserViewEntry.fromKernelEntry(entry.*);
        }
        // Write generation counter into self-entry's field1 (after fromKernelEntry overwrites it)
        @atomicStore(u64, &view_ptr[0].field1, self.perm_view_gen, .release);
        // Wake any userspace waiters on this field
        const gen_paddr = PAddr.fromInt(self.perm_view_phys.addr + @offsetOf(UserViewEntry, "field1"));
        _ = futex.wake(gen_paddr, 0xFFFF_FFFF);
    }

    /// Insert a thread handle into this process's perm table.
    /// Returns the handle ID on success.
    pub fn insertThreadHandle(self: *Process, thread: *Thread, rights: ThreadHandleRights) !u64 {
        return self.insertPerm(.{
            .handle = 0,
            .object = .{ .thread = thread },
            .rights = @as(u16, @as(u8, @bitCast(rights))),
        });
    }

    /// Insert a thread handle at a specific slot (used for initial thread at slot 1).
    pub fn insertThreadHandleAtSlot(self: *Process, slot: usize, thread: *Thread, rights: ThreadHandleRights) void {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
        // Caller must guarantee the target slot is empty — initPermTable
        // leaves slots 1..MAX_PERMS-1 empty, which is why this works for
        // the initial thread at slot 1. If a future caller tries to
        // overwrite an occupied slot we'd silently drop a reference.
        std.debug.assert(self.perm_table[slot].object == .empty);
        const handle_id = self.handle_counter;
        self.handle_counter += 1;
        self.perm_table[slot] = .{
            .handle = handle_id,
            .object = .{ .thread = thread },
            .rights = @as(u16, @as(u8, @bitCast(rights))),
        };
        self.perm_count += 1;
        self.syncUserView();
    }

    /// Remove all thread handles for a specific thread from this process's perm table.
    pub fn removeThreadHandle(self: *Process, thread: *Thread) void {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
        var removed = false;
        for (&self.perm_table) |*slot| {
            if (slot.object == .thread and slot.object.thread == thread) {
                slot.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
                removed = true;
                break;
            }
        }
        if (removed) self.syncUserView();
    }

    /// Find the handle ID for a thread in this process's perm table.
    pub fn findThreadHandle(self: *Process, thread: *Thread) ?u64 {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
        for (self.perm_table) |slot| {
            if (slot.object == .thread and slot.object.thread == thread) {
                return slot.handle;
            }
        }
        return null;
    }

    /// Release the fault-handler relationship between `self` (the handler)
    /// and `target` without killing the target. Called when:
    /// - the handler revokes its process handle to target with the fault_handler bit
    /// - the handler dies (cleanupPhase1 walks fault_handler_targets)
    /// - target dies (cleanup unlinks itself from handler's list)
    pub fn releaseFaultHandler(self: *Process, target: *Process) void {
        // Clear all thread-handle slots in self.perm_table that belong to target.
        self.perm_lock.lock();
        for (&self.perm_table) |*slot| {
            if (slot.object == .thread and slot.object.thread.process == target) {
                slot.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
            }
        }
        self.syncUserView();
        self.perm_lock.unlock();

        // Clear target's pointer back to handler and restore fault_handler
        // bit on slot 0 — but only if the target originally had the bit.
        // This prevents synthesizing a right that the sender didn't hold
        // at the moment of the fault_handler transfer.
        target.perm_lock.lock();
        target.fault_handler_proc = null;
        if (target.had_self_fault_handler) {
            var self_rights = target.perm_table[0].processRights();
            self_rights.fault_handler = true;
            target.perm_table[0].rights = @bitCast(self_rights);
        }
        target.syncUserView();
        target.perm_lock.unlock();

        // Drain any fault-box state belonging to the target. The threads
        // are still alive — they'll be re-evaluated under self-handling
        // semantics below.
        self.fault_box.lock.lock();
        if (self.fault_box.isPendingReply()) {
            if (self.fault_box.pending_thread) |pt| {
                if (pt.process == target) {
                    _ = self.fault_box.endPendingReplyLocked();
                }
            }
        }
        var prev: ?*Thread = null;
        var cur = self.fault_box.queue_head;
        while (cur) |t| {
            const next_t = t.next;
            if (t.process == target) {
                if (prev) |p| p.next = next_t else self.fault_box.queue_head = next_t;
                if (self.fault_box.queue_tail == t) self.fault_box.queue_tail = prev;
                t.next = null;
            } else {
                prev = t;
            }
            cur = next_t;
        }
        self.fault_box.lock.unlock();

        // §2.12.35: re-evaluate target's threads under self-handling.
        // - .suspended threads (from external stop-all) → .ready + enqueue.
        // - .faulted threads → push onto target's own fault_box so a sibling
        //   can recv them. Their state stays .faulted.
        // - If after re-eval no thread is alive (all .faulted), kill the
        //   process per §2.12.9.
        target.lock.lock();
        var resume_buf: [MAX_THREADS]*Thread = undefined;
        var resume_n: usize = 0;
        var faulted_buf: [MAX_THREADS]*Thread = undefined;
        var faulted_n: usize = 0;
        for (target.threads[0..target.num_threads]) |t| {
            if (t.state == .suspended) {
                t.state = .ready;
                resume_buf[resume_n] = t;
                resume_n += 1;
            } else if (t.state == .faulted) {
                faulted_buf[faulted_n] = t;
                faulted_n += 1;
            }
        }
        target.suspended_thread_slots = 0;
        // Count alive threads (not .faulted, not .exited).
        var alive: u64 = 0;
        for (target.threads[0..target.num_threads]) |t| {
            if (t.state != .faulted and t.state != .exited) alive += 1;
        }
        target.lock.unlock();

        for (resume_buf[0..resume_n]) |t| {
            const target_core = if (t.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
            sched.enqueueOnCore(target_core, t);
        }

        if (alive == 0 and faulted_n > 0) {
            // No surviving thread to call fault_recv. §2.12.9: kill.
            target.kill(.killed);
        } else {
            // Push the faulted threads onto target's own fault_box.
            target.fault_box.lock.lock();
            for (faulted_buf[0..faulted_n]) |t| {
                if (target.fault_box.isReceiving()) {
                    const r = target.fault_box.takeReceiverLocked();
                    target.fault_box.beginPendingReplyLocked(t);
                    target.fault_box.lock.unlock();
                    deliverFaultToWaiter(target, r, t);
                    target.fault_box.lock.lock();
                } else {
                    target.fault_box.enqueueLocked(t);
                }
            }
            target.fault_box.lock.unlock();
        }

        // Unlink target from self.fault_handler_targets list.
        self.unlinkFaultHandlerTarget(target);
    }

    /// Link a target process into this handler's fault_handler_targets list.
    /// Returns true on success; returns false if `self` (the handler) is no
    /// longer alive, meaning the caller must roll the link back (revert
    /// target->fault_handler_proc to self-handling). This races with
    /// cleanupPhase1 of `self`; holding self.lock during the alive check
    /// serializes us with kill() which transitions alive→false under the
    /// same lock.
    pub fn linkFaultHandlerTarget(self: *Process, target: *Process) bool {
        self.lock.lock();
        defer self.lock.unlock();
        if (!self.alive) return false;
        // Avoid double-link
        var cur = self.fault_handler_targets_head;
        while (cur) |c| {
            if (c == target) return true;
            cur = c.fault_handler_targets_next;
        }
        target.fault_handler_targets_next = self.fault_handler_targets_head;
        self.fault_handler_targets_head = target;
        return true;
    }

    /// Unlink a target from this handler's fault_handler_targets list.
    pub fn unlinkFaultHandlerTarget(self: *Process, target: *Process) void {
        self.lock.lock();
        defer self.lock.unlock();
        var prev: ?*Process = null;
        var cur = self.fault_handler_targets_head;
        while (cur) |c| {
            if (c == target) {
                if (prev) |p| {
                    p.fault_handler_targets_next = c.fault_handler_targets_next;
                } else {
                    self.fault_handler_targets_head = c.fault_handler_targets_next;
                }
                target.fault_handler_targets_next = null;
                return;
            }
            prev = c;
            cur = c.fault_handler_targets_next;
        }
    }

    /// Materialize a FaultMessage for `faulted` and write it into the
    /// receiver process's user buffer at `buf_ptr` via physmap. Used by
    /// faultBlock direct-delivery: the receiver thread is blocked in
    /// sysFaultRecv and cannot itself dequeue + write on resume, so the
    /// sender (the faulting thread's kernel context) does it.
    fn writeFaultMessageInto(
        receiver_proc: *Process,
        buf_ptr: u64,
        process_handle: u64,
        thread_handle: u64,
        faulted: *Thread,
    ) void {
        // Layout matches libz.FaultMessage. 176 bytes total.
        var msg: [176]u8 = undefined;
        @as(*align(1) u64, @ptrCast(&msg[0])).* = process_handle;
        @as(*align(1) u64, @ptrCast(&msg[8])).* = thread_handle;
        msg[16] = @intFromEnum(faulted.fault_reason);
        @memset(msg[17..24], 0);
        @as(*align(1) u64, @ptrCast(&msg[24])).* = faulted.fault_addr;
        @as(*align(1) u64, @ptrCast(&msg[32])).* = faulted.fault_rip;
        @as(*align(1) u64, @ptrCast(&msg[40])).* = faulted.ctx.rflags;
        @as(*align(1) u64, @ptrCast(&msg[48])).* = faulted.ctx.rsp;
        const r = &faulted.ctx.regs;
        const gprs = [_]u64{
            r.r15, r.r14, r.r13, r.r12, r.r11, r.r10, r.r9, r.r8,
            r.rdi, r.rsi, r.rbp, r.rbx, r.rdx, r.rcx, r.rax,
        };
        var off: usize = 56;
        for (gprs) |v| {
            @as(*align(1) u64, @ptrCast(&msg[off])).* = v;
            off += 8;
        }

        // Walk the receiver's page table and copy the message via physmap.
        var remaining: usize = 176;
        var src_off: usize = 0;
        var dst_va: u64 = buf_ptr;
        while (remaining > 0) {
            const page_off = dst_va & 0xFFF;
            const chunk = @min(remaining, paging.PAGE4K - page_off);
            const page_paddr = arch.resolveVaddr(receiver_proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return;
            const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;
            const dst: [*]u8 = @ptrFromInt(physmap_addr);
            @memcpy(dst[0..chunk], msg[src_off..][0..chunk]);
            src_off += chunk;
            dst_va += chunk;
            remaining -= chunk;
        }
    }

    /// Look up the handle IDs that should appear in a FaultMessage when
    /// `faulted` is delivered to `handler`. Returns (process_handle,
    /// thread_handle) — both fields are looked up in `handler`'s perm
    /// table; either can be 0 (HANDLE_SELF / not present).
    fn lookupHandlesForFault(handler: *Process, faulted: *Thread) struct { proc_h: u64, thread_h: u64 } {
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

    /// Direct-deliver `faulted` to a thread blocked on fault_recv.
    /// Materializes the FaultMessage in the receiver's user buffer (via
    /// physmap into the receiver's address space), sets the receiver's
    /// saved rax to the fault token (= thread handle), and wakes it.
    fn deliverFaultToWaiter(handler: *Process, receiver: *Thread, faulted: *Thread) void {
        // The receiver was blocked inside sysFaultRecv. The buf_ptr arg
        // is in receiver.ctx.regs.rdi (preserved from int 0x80 entry).
        const buf_ptr = receiver.ctx.regs.rdi;
        const handles = lookupHandlesForFault(handler, faulted);
        writeFaultMessageInto(receiver.process, buf_ptr, handles.proc_h, handles.thread_h, faulted);
        // Set the syscall return value: fault_recv returns the thread
        // handle (= the fault token) on success.
        receiver.ctx.regs.rax = handles.thread_h;
        wakeReceiver(receiver);
    }

    /// Wake a thread that was blocked on recv/fault_recv. Spins on
    /// `on_cpu` to make sure the thread is fully off-CPU before changing
    /// its state and re-enqueuing.
    fn wakeReceiver(t: *Thread) void {
        while (t.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        t.state = .ready;
        const target_core = if (t.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
        sched.enqueueOnCore(target_core, t);
    }

    /// Resolve the process that should handle this process's faults.
    /// Returns null if no handler exists (caller must kill). Per
    /// `systems.md:876`, a process with `fault_handler_proc == null`
    /// self-handles iff it holds the `fault_handler` ProcessRight bit on
    /// slot 0; otherwise it has no handler at all.
    fn faultHandlerOf(self: *Process) ?*Process {
        if (self.fault_handler_proc) |h| return h;
        if (self.perm_table[0].processRights().fault_handler) return self;
        return null;
    }

    /// Block the calling thread on a fault: enqueue it on the appropriate
    /// fault box, suspend sibling threads (stop-all) for external handlers,
    /// mark this thread .faulted. Returns true if the fault was queued
    /// (caller should yield); false if no handler or the process must die
    /// immediately (§2.12.7 / §2.12.9).
    ///
    /// Fault metadata is written directly to the thread's own fields. The
    /// thread itself is the queued unit on the fault box — `thread.next`
    /// links into the queue, and the saved register snapshot lives in
    /// `thread.ctx.regs` (already populated by the exception entry stub).
    pub fn faultBlock(self: *Process, thread: *Thread, reason: FaultReason, fault_addr: u64, rip: u64, user_ctx: ?*ArchCpuContext) bool {
        const handler = self.faultHandlerOf() orelse return false;

        // Stamp the fault payload onto the thread itself.
        thread.fault_reason = reason;
        thread.fault_addr = fault_addr;
        thread.fault_rip = rip;
        // Stash pointer to the user iret frame for FAULT_RESUME_MODIFIED.
        // Once the scheduler yields out of this thread, `thread.ctx` will
        // point at a kernel-mode context and no longer refers to the user
        // frame that the stub will iret through on resume.
        thread.fault_user_ctx = user_ctx;

        if (handler == self) {
            // Self-handling: §2.12.7 / §2.12.8 / §2.12.9. No stop-all — sibling
            // threads continue running so they can call fault_recv on our own
            // fault box.
            self.lock.lock();
            // Count threads that are actually runnable and could call
            // fault_recv on our own box. §2.12.9 requires kill/restart if
            // there are no surviving receivers. `.exited` threads are gone,
            // `.suspended` threads cannot be scheduled, `.faulted` threads
            // are blocked awaiting their own handler — none of them can
            // service a fault. We include the currently-faulting thread
            // itself in `alive` (it hasn't been marked .faulted yet below),
            // so the check is `alive <= 1` (only us = no one else).
            var alive: u64 = 0;
            for (self.threads[0..self.num_threads]) |t| {
                if (t == thread) continue;
                switch (t.state) {
                    .ready, .running, .blocked => alive += 1,
                    .faulted, .suspended, .exited => {},
                }
            }
            // Add 1 for ourselves so the existing <=1 comparison still means
            // "no other thread can service us".
            alive += 1;
            if (alive <= 1) {
                // §2.12.7 / §2.12.9: no surviving thread to call fault_recv;
                // the spec mandates immediate kill/restart with no message
                // delivered.
                self.lock.unlock();
                return false;
            }
            thread.state = .faulted;
            self.faulted_thread_slots |= @as(u64, 1) << @intCast(thread.slot_index);
            self.lock.unlock();

            // If a sibling is blocked on fault_recv, deliver directly into
            // its user buffer (the receiver cannot dequeue itself on
            // wake-up because the kernel doesn't restart sysFaultRecv).
            // Otherwise enqueue and let the next fault_recv pick it up.
            self.fault_box.lock.lock();
            if (self.fault_box.isReceiving()) {
                const r = self.fault_box.takeReceiverLocked();
                self.fault_box.beginPendingReplyLocked(thread);
                self.fault_box.lock.unlock();
                deliverFaultToWaiter(self, r, thread);
                return true;
            }
            self.fault_box.enqueueLocked(thread);
            self.fault_box.lock.unlock();
            return true;
        }

        // External handler path (§2.12.10): possibly stop-all + enqueue on
        // handler's box.
        //
        // §2.12.11: before stop-all, check the faulting thread's
        // exclude_oneshot / exclude_permanent flags on its perm entry in
        // the handler's table. If either is set, skip stop-all (only the
        // faulting thread enters .faulted). exclude_oneshot is consumed.
        var stop_all = true;
        handler.perm_lock.lock();
        for (&handler.perm_table) |*slot| {
            if (slot.object == .thread and slot.object.thread == thread) {
                if (slot.exclude_oneshot or slot.exclude_permanent) {
                    stop_all = false;
                    if (slot.exclude_oneshot) slot.exclude_oneshot = false;
                }
                break;
            }
        }
        handler.perm_lock.unlock();

        // §2.12.23 stop-all: every sibling thread that is currently runnable
        // (.ready or .running) is moved to .suspended.
        self.lock.lock();
        if (stop_all) {
            for (self.threads[0..self.num_threads]) |sib| {
                if (sib == thread) continue;
                if (sib.state == .running or sib.state == .ready) {
                    sib.state = .suspended;
                    self.suspended_thread_slots |= @as(u64, 1) << @intCast(sib.slot_index);
                }
            }
        }
        thread.state = .faulted;
        self.faulted_thread_slots |= @as(u64, 1) << @intCast(thread.slot_index);
        self.lock.unlock();

        handler.fault_box.lock.lock();
        if (handler.fault_box.isReceiving()) {
            const r = handler.fault_box.takeReceiverLocked();
            handler.fault_box.beginPendingReplyLocked(thread);
            handler.fault_box.lock.unlock();
            deliverFaultToWaiter(handler, r, thread);
        } else {
            handler.fault_box.enqueueLocked(thread);
            handler.fault_box.lock.unlock();
        }

        return true;
    }

    pub fn getPermByHandle(self: *Process, handle_id: u64) ?PermissionEntry {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
        return self.getPermByHandleLocked(handle_id);
    }

    /// Look up a handle while the caller already holds perm_lock.
    pub fn getPermByHandleLocked(self: *const Process, handle_id: u64) ?PermissionEntry {
        for (self.perm_table) |entry| {
            if (entry.object != .empty and entry.handle == handle_id) return entry;
        }
        return null;
    }

    pub fn insertPerm(self: *Process, entry_in: PermissionEntry) !u64 {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
        for (self.perm_table[1..]) |*slot| {
            if (slot.object == .empty) {
                const handle_id = self.handle_counter;
                self.handle_counter += 1;
                slot.* = entry_in;
                slot.handle = handle_id;
                self.perm_count += 1;
                // Increment refcount on referenced process
                switch (entry_in.object) {
                    .process => |p| _ = @atomicRmw(u32, &p.handle_refcount, .Add, 1, .acq_rel),
                    .dead_process => |p| _ = @atomicRmw(u32, &p.handle_refcount, .Add, 1, .acq_rel),
                    else => {},
                }
                self.syncUserView();
                return handle_id;
            }
        }
        return error.PermTableFull;
    }

    pub fn removePerm(self: *Process, handle_id: u64) !void {
        if (handle_id == HANDLE_SELF) return error.CannotRevokeSelf;
        var referenced_proc: ?*Process = null;
        self.perm_lock.lock();
        for (self.perm_table[1..]) |*slot| {
            if (slot.object != .empty and slot.handle == handle_id) {
                switch (slot.object) {
                    .process => |p| referenced_proc = p,
                    .dead_process => |p| referenced_proc = p,
                    else => {},
                }
                slot.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
                self.syncUserView();
                self.perm_lock.unlock();
                // Decrement refcount outside perm_lock to avoid lock ordering issues
                if (referenced_proc) |p| {
                    const prev = @atomicRmw(u32, &p.handle_refcount, .Sub, 1, .acq_rel);
                    if (prev == 1 and p.cleanup_complete) {
                        allocator.destroy(p);
                    }
                }
                return;
            }
        }
        self.perm_lock.unlock();
        return error.NotFound;
    }

    pub fn removeChild(self: *Process, child: *Process) void {
        self.lock.lock();
        defer self.lock.unlock();
        for (self.children[0..self.num_children], 0..) |c, i| {
            if (c == child) {
                self.num_children -= 1;
                if (i < self.num_children) {
                    self.children[i] = self.children[self.num_children];
                }
                return;
            }
        }
    }

    pub fn removeThread(self: *Process, thread: *Thread) bool {
        self.lock.lock();
        defer self.lock.unlock();
        for (self.threads[0..self.num_threads], 0..) |t, i| {
            if (t == thread) {
                self.num_threads -= 1;
                if (i < self.num_threads) {
                    self.threads[i] = self.threads[self.num_threads];
                    self.threads[i].slot_index = @intCast(i);
                }
                return self.num_threads == 0;
            }
        }
        unreachable;
    }

    pub fn kill(self: *Process, reason: CrashReason) void {
        self.lock.lock();
        if (!self.alive) {
            self.lock.unlock();
            return;
        }
        self.fault_reason = reason;
        const should_restart = self.restart_context != null;
        if (!should_restart) {
            self.alive = false;
        }

        // Collect blocked/faulted/suspended threads before marking all exited.
        // These are off-CPU and need explicit deinit (they won't be picked up
        // by the scheduler-zombie path because they're not currently running).
        var blocked: [MAX_THREADS]*Thread = undefined;
        var num_blocked: u32 = 0;
        for (self.threads[0..self.num_threads]) |thread| {
            if (thread.state == .blocked or thread.state == .faulted or thread.state == .suspended) {
                blocked[num_blocked] = thread;
                num_blocked += 1;
            }
            thread.state = .exited;
        }
        self.faulted_thread_slots = 0;
        self.suspended_thread_slots = 0;
        self.lock.unlock();

        // Remove blocked threads from external wait structures and deinit them.
        // Each deinit calls removeThread which decrements num_threads.
        // The last thread's deinit triggers lastThreadExited.
        for (blocked[0..num_blocked]) |thread| {
            // Wait until the thread is fully off-CPU before freeing its
            // kernel stack. .suspended and .faulted threads may still be in
            // the middle of a syscall on their kernel stack.
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            // A thread that was .ready when stop-all marked it .suspended is
            // still linked into a per-core run queue. Remove it before
            // deinit, otherwise the dangling pointer in the queue is a UAF
            // waiting to happen on the next dequeue.
            sched.removeFromAnyRunQueue(thread);
            if (thread.futex_paddr.addr != 0) {
                futex.removeBlockedThread(thread);
            }
            if (thread.ipc_server) |server| {
                server.msg_box.lock.lock();
                if (server.msg_box.isPendingReply() and server.msg_box.pending_thread == thread) {
                    _ = server.msg_box.endPendingReplyLocked();
                } else {
                    _ = server.msg_box.removeLocked(thread);
                }
                thread.ipc_server = null;
                server.msg_box.lock.unlock();
            }
            // Scrub from any fault box that may still hold this thread
            // pointer. cleanupPhase1 also drains the boxes, but that runs
            // only after lastThreadExited — between deinit calls in this
            // loop, freed pointers would otherwise be visible to a
            // concurrent fault_recv on another core.
            scrubFromFaultBox(&self.fault_box, thread);
            if (self.fault_handler_proc) |handler| {
                scrubFromFaultBox(&handler.fault_box, thread);
            }
            thread.deinit();
        }

        // Edge case: process had 0 threads (shouldn't happen normally).
        if (self.num_threads == 0 and num_blocked == 0) {
            if (should_restart) {
                self.performRestart();
            } else {
                self.doExit();
            }
        }
    }

    pub fn killSubtree(self: *Process) void {
        var i: u64 = 0;
        while (i < self.num_children) : (i += 1) {
            self.children[i].killSubtree();
        }
        self.kill(.killed);
    }

    pub fn disableRestart(self: *Process) void {
        self.lock.lock();
        if (self.restart_context) |rc| {
            restart_context_mod.destroy(rc);
            self.restart_context = null;
        }
        self.lock.unlock();

        // §2.3.4: clear the restart bit from slot 0 of our own permission
        // table and publish to the user view so userspace observes that the
        // capability is gone.
        self.perm_lock.lock();
        var self_rights = self.perm_table[0].processRights();
        self_rights.restart = false;
        self.perm_table[0].rights = @bitCast(self_rights);
        self.syncUserView();
        self.perm_lock.unlock();

        var i: u64 = 0;
        while (i < self.num_children) : (i += 1) {
            self.children[i].disableRestart();
        }
    }

    pub fn lastThreadExited(self: *Process) void {
        if (!self.alive) {
            // Process was killed — cleanup was deferred until last thread deinit.
            self.doExit();
            return;
        }
        self.exit();
    }

    pub fn exit(self: *Process) void {
        self.lock.lock();
        if (!self.alive) {
            self.lock.unlock();
            return;
        }
        if (self.fault_reason == .none) {
            self.fault_reason = .normal_exit;
        }
        const should_restart = self.restart_context != null;
        if (!should_restart) {
            self.alive = false;
        }
        self.lock.unlock();

        if (should_restart) {
            self.performRestart();
            return;
        }

        self.doExit();
    }

    fn doExit(self: *Process) void {
        self.cleanupPhase1();

        if (self.num_children == 0) {
            // Leaf process: cleanupPhase2 runs immediately and handles
            // the parent's convertToDeadProcess call internally.
            self.cleanupPhase2();
        } else {
            // Zombie: has children, so cleanupPhase2 is deferred until
            // the last child's cleanupPhase2 cascades back to us. Convert
            // the parent's entry now so the parent can observe the death.
            if (self.parent) |p| {
                p.convertToDeadProcess(self);
            }
        }
    }

    fn performRestart(self: *Process) void {
        const rc = self.restart_context orelse {
            self.cleanupPhase1();
            if (self.num_children == 0) {
                self.cleanupPhase2();
            }
            return;
        };

        self.restart_count +%= 1;

        // Preserve IPC wait list across restart. If there's a pending caller
        // (message was delivered but not replied to), re-enqueue it at the
        // head so the restarted process can recv it again. Drop the
        // receiver — that thread is dead with the rest of the process.
        self.msg_box.lock.lock();
        const restored_caller: ?*Thread = if (self.msg_box.isPendingReply())
            self.msg_box.endPendingReplyLocked()
        else
            null;
        if (restored_caller) |pc| {
            pc.next = self.msg_box.queue_head;
            self.msg_box.queue_head = pc;
            if (self.msg_box.queue_tail == null) {
                self.msg_box.queue_tail = pc;
            }
        }
        if (self.msg_box.isReceiving()) {
            _ = self.msg_box.takeReceiverLocked();
        }
        self.msg_box.lock.unlock();

        self.vmm.resetForRestart();

        // Clean up thread handles from own perm table and handler's perm table
        if (self.fault_handler_proc) |handler| {
            handler.perm_lock.lock();
            for (&handler.perm_table) |*slot| {
                if (slot.object == .thread) {
                    const t = slot.object.thread;
                    if (t.process == self) {
                        slot.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                        handler.perm_count -= 1;
                    }
                }
            }
            handler.syncUserView();
            handler.perm_lock.unlock();

            // §2.6.35: also drain the handler's fault_box of any entries
            // pointing at our threads. The threads have already been
            // deinit'd by the kill() path, so the queue holds dangling
            // pointers — must scrub before the handler can recv again.
            handler.fault_box.lock.lock();
            if (handler.fault_box.isPendingReply()) {
                if (handler.fault_box.pending_thread) |pt| {
                    if (pt.process == self) {
                        _ = handler.fault_box.endPendingReplyLocked();
                    }
                }
            }
            var prev: ?*Thread = null;
            var cur = handler.fault_box.queue_head;
            while (cur) |t| {
                const next_t = t.next;
                if (t.process == self) {
                    if (prev) |p| p.next = next_t else handler.fault_box.queue_head = next_t;
                    if (handler.fault_box.queue_tail == t) handler.fault_box.queue_tail = prev;
                    t.next = null;
                } else {
                    prev = t;
                }
                cur = next_t;
            }
            handler.fault_box.lock.unlock();
        }

        // Drain our own fault_box too — when self-handling, queued faulting
        // threads are our own dead threads.
        self.fault_box.lock.lock();
        if (self.fault_box.isPendingReply()) {
            _ = self.fault_box.endPendingReplyLocked();
        }
        if (self.fault_box.isReceiving()) {
            _ = self.fault_box.takeReceiverLocked();
        }
        while (self.fault_box.dequeueLocked()) |_| {}
        self.fault_box.lock.unlock();

        self.perm_lock.lock();
        for (&self.perm_table) |*entry| {
            if (entry.object == .vm_reservation or entry.object == .thread) {
                entry.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
            }
        }
        self.faulted_thread_slots = 0;
        self.suspended_thread_slots = 0;
        self.syncUserView();
        self.perm_lock.unlock();

        self.updateParentView();

        if (rc.data_segment.ghost.len > 0) {
            writeToUserPages(
                self.addr_space_root,
                rc.data_segment.vaddr.addr,
                rc.data_segment.ghost,
            );

            // Zero partial-page BSS: the bytes between the end of initialized data
            // and the next page boundary are BSS that lives on the same page as the
            // data segment tail. The .decommit node only covers full BSS pages;
            // this partial page is in the .preserve node and must be zeroed explicitly.
            const data_end = rc.data_segment.vaddr.addr + rc.data_segment.ghost.len;
            const next_page = std.mem.alignForward(u64, data_end, paging.PAGE4K);
            const tail_len = next_page - data_end;
            if (tail_len > 0 and tail_len < paging.PAGE4K) {
                const page_base = std.mem.alignBackward(u64, data_end, paging.PAGE4K);
                const page_offset = data_end - page_base;
                if (arch.resolveVaddr(self.addr_space_root, VAddr.fromInt(page_base))) |paddr| {
                    const physmap_addr = VAddr.fromPAddr(paddr, null).addr + page_offset;
                    const dst: [*]u8 = @ptrFromInt(physmap_addr);
                    @memset(dst[0..tail_len], 0);
                }
            }
        }

        const thread = thread_mod.Thread.create(self, rc.entry_point, self.perm_view_vaddr.addr, DEFAULT_STACK_PAGES) catch return;

        // Insert initial thread handle at slot 1
        self.insertThreadHandleAtSlot(1, thread, self.thread_handle_rights);

        // If external fault handler, insert thread handle into handler's perm table.
        // On E_MAXCAP (handler's table is full), fall back to self-fault-handling:
        // revert the fault_handler relationship so the restarted process handles
        // its own faults. Spec §2.6.35 / §2.12.5 require the thread handle to be
        // inserted; if we can't, self-handling is the safe degradation.
        if (self.fault_handler_proc) |handler| {
            if (handler.insertThreadHandle(thread, ThreadHandleRights.full)) |_| {
                // OK
            } else |_| {
                handler.releaseFaultHandler(self);
            }
        }

        sched.enqueueOnCore(arch.coreID(), thread);
    }

    fn updateParentView(self: *Process) void {
        const parent = self.parent orelse return;
        parent.perm_lock.lock();
        defer parent.perm_lock.unlock();
        for (parent.perm_table[1..], 1..) |*slot, idx| {
            const matches = switch (slot.object) {
                .process => |p| @intFromPtr(p) == @intFromPtr(self),
                else => false,
            };
            if (matches) {
                parent.syncUserView();
                if (parent.perm_view_phys.addr != 0) {
                    const field0_pa = PAddr.fromInt(parent.perm_view_phys.addr + idx * @sizeOf(UserViewEntry) + @offsetOf(UserViewEntry, "field0"));
                    _ = futex.wake(field0_pa, 1);
                }
                return;
            }
        }
    }

    fn cleanupIpcState(self: *Process) void {
        self.msg_box.lock.lock();

        // Drain all queued waiters with E_NOENT.
        while (self.msg_box.dequeueLocked()) |w| {
            w.ipc_server = null;
            w.ctx.regs.rax = @bitCast(@as(i64, -10));
            while (w.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            w.state = .ready;
            const target_core = if (w.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
            sched.enqueueOnCore(target_core, w);
        }

        // Unblock the pending caller (delivered but not replied) if any.
        if (self.msg_box.isPendingReply()) {
            if (self.msg_box.endPendingReplyLocked()) |pc| {
                pc.ipc_server = null;
                pc.ctx.regs.rax = @bitCast(@as(i64, -10));
                while (pc.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
                pc.state = .ready;
                const target_core = if (pc.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
                sched.enqueueOnCore(target_core, pc);
            }
        }

        // Drop the receiver (its thread is dead too — we're tearing down).
        if (self.msg_box.isReceiving()) {
            _ = self.msg_box.takeReceiverLocked();
        }

        self.msg_box.lock.unlock();

        // Clean up threads that are blocked waiting for reply from other processes
        for (self.threads[0..self.num_threads]) |thread| {
            if (thread.ipc_server) |server| {
                server.msg_box.lock.lock();
                if (server.msg_box.isPendingReply() and server.msg_box.pending_thread == thread) {
                    _ = server.msg_box.endPendingReplyLocked();
                } else {
                    _ = server.msg_box.removeLocked(thread);
                }
                thread.ipc_server = null;
                server.msg_box.lock.unlock();
            }
        }
    }

    fn cleanupPhase1(self: *Process) void {
        // §2.12.35: if we are a fault handler for other processes, revert
        // each target to self-handling before tearing down our perm table.
        while (true) {
            self.lock.lock();
            const target = self.fault_handler_targets_head;
            self.lock.unlock();
            const t = target orelse break;
            // releaseFaultHandler unlinks t from our list, so loop terminates.
            self.releaseFaultHandler(t);
        }

        // If we have an external fault handler, unlink ourselves from its
        // list and drain any of our threads from its fault box. We don't
        // call releaseFaultHandler on the handler because that would touch
        // our own perm table while we're in the middle of cleanup.
        if (self.fault_handler_proc) |handler| {
            handler.unlinkFaultHandlerTarget(self);
            handler.fault_box.lock.lock();
            // Drop pending_thread if it points at one of ours.
            if (handler.fault_box.isPendingReply()) {
                if (handler.fault_box.pending_thread) |pt| {
                    if (pt.process == self) {
                        _ = handler.fault_box.endPendingReplyLocked();
                    }
                }
            }
            // Drain any of our queued threads from the handler's box.
            var prev: ?*Thread = null;
            var cur = handler.fault_box.queue_head;
            while (cur) |t| {
                const next_t = t.next;
                if (t.process == self) {
                    if (prev) |p| p.next = next_t else handler.fault_box.queue_head = next_t;
                    if (handler.fault_box.queue_tail == t) handler.fault_box.queue_tail = prev;
                    t.next = null;
                } else {
                    prev = t;
                }
                cur = next_t;
            }
            handler.fault_box.lock.unlock();
            self.fault_handler_proc = null;
        }

        self.cleanupIpcState();
        self.cleanupDmaMappings();
        self.vmm.deinit();

        // Slot 0 (HANDLE_SELF) is populated by initPermTable without going
        // through insertPerm, so it never incremented our own handle_refcount
        // on entry. Skip it here to keep the counter symmetric — otherwise
        // a process with no external holders would underflow the u32 and
        // cleanupPhase2's refcount==0 check would never fire, leaking the
        // struct; and with external holders, we'd off-by-one the other way
        // and destroy the struct prematurely.
        for (self.perm_table[1..]) |*entry| {
            switch (entry.object) {
                .shared_memory => |shm| shm.decRef(),
                .device_region => |device| {
                    returnDeviceHandleUpTree(self, entry.rights, device);
                },
                .core_pin => |cp| {
                    sched.unpinByRevoke(cp.core_id, 0);
                },
                .thread => {},
                .process => |p| {
                    const prev = @atomicRmw(u32, &p.handle_refcount, .Sub, 1, .acq_rel);
                    if (prev == 1 and p.cleanup_complete) {
                        allocator.destroy(p);
                    }
                },
                .dead_process => |p| {
                    const prev = @atomicRmw(u32, &p.handle_refcount, .Sub, 1, .acq_rel);
                    if (prev == 1 and p.cleanup_complete) {
                        allocator.destroy(p);
                    }
                },
                .vm_reservation, .empty => {},
            }
            entry.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
        }
        // Clear slot 0 without touching refcount.
        self.perm_table[0] = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };

        arch.freeUserAddrSpace(self.addr_space_root);
    }

    fn cleanupPhase2(self: *Process) void {
        if (self.parent) |p| {
            p.removeChild(self);
            p.convertToDeadProcess(self);

            if (!p.alive and p.num_children == 0) {
                p.cleanupPhase2();
            }
        }

        if (self.restart_context) |rc| restart_context_mod.destroy(rc);

        self.cleanup_complete = true;
        // Only free if no external handles remain
        if (@atomicLoad(u32, &self.handle_refcount, .acquire) == 0) {
            allocator.destroy(self);
        }
    }

    /// Convert a live `process` entry in `holder`'s perm table to
    /// `dead_process`. Called from doExit (zombie path) and cleanupPhase2
    /// (leaf path), and also lazily from IPC paths when a send/call
    /// discovers the target is dead.
    /// Convert ALL live `process` entries for `child` in `holder`'s perm
    /// table to `dead_process`. A holder can have multiple handles to the
    /// same child (e.g. one from proc_create, another from cap transfer).
    pub fn convertToDeadProcess(holder: *Process, child: *Process) void {
        holder.perm_lock.lock();
        defer holder.perm_lock.unlock();
        var converted = false;
        for (holder.perm_table[1..], 1..) |*slot, idx| {
            const matches = switch (slot.object) {
                .process => |p| @intFromPtr(p) == @intFromPtr(child),
                else => false,
            };
            if (matches) {
                slot.object = .{ .dead_process = child };
                converted = true;
                if (holder.perm_view_phys.addr != 0) {
                    const field0_pa = PAddr.fromInt(holder.perm_view_phys.addr + idx * @sizeOf(UserViewEntry) + @offsetOf(UserViewEntry, "field0"));
                    _ = futex.wake(field0_pa, 1);
                }
            }
        }
        if (converted) holder.syncUserView();
    }

    pub fn addDmaMapping(self: *Process, device: *DeviceRegion, shm: *SharedMemory, dma_base: u64, num_pages: u64) !void {
        if (self.num_dma_mappings >= MAX_DMA_MAPPINGS) return error.TooManyDmaMappings;
        self.dma_mappings[self.num_dma_mappings] = .{
            .device = device,
            .shm = shm,
            .dma_base = dma_base,
            .num_pages = num_pages,
            .active = true,
        };
        self.num_dma_mappings += 1;
    }

    pub fn removeDmaMapping(self: *Process, device: *DeviceRegion, shm: *SharedMemory) ?DmaMapping {
        for (self.dma_mappings[0..self.num_dma_mappings], 0..) |*m, i| {
            if (m.active and m.device == device and m.shm == shm) {
                const mapping = m.*;
                m.active = false;
                if (i == self.num_dma_mappings - 1) {
                    self.num_dma_mappings -= 1;
                }
                return mapping;
            }
        }
        return null;
    }

    pub fn cleanupDmaMappings(self: *Process) void {
        for (self.dma_mappings[0..self.num_dma_mappings]) |*m| {
            if (m.active) {
                arch.unmapDmaPages(m.device, m.dma_base, m.num_pages);
                m.active = false;
            }
        }
        self.num_dma_mappings = 0;
    }

    pub fn returnDeviceHandleUpTree(source: *Process, rights: u16, device: *DeviceRegion) void {
        var ancestor = source.parent;
        while (ancestor) |anc| {
            if (anc.alive) {
                if (anc.insertPerm(.{
                    .handle = 0,
                    .object = .{ .device_region = device },
                    .rights = rights,
                })) |_| {
                    return;
                } else |_| {
                    // Table full — continue walk to next ancestor (§2.1.11).
                }
            }
            ancestor = anc.parent;
        }
    }

    pub fn create(elf_binary: []const u8, initial_rights: ProcessRights, parent: ?*Process, thr_rights: ThreadHandleRights, max_priority: Priority) !*Process {
        const proc = try allocator.create(Process);
        // The late-stage TooManyChildren branch below calls proc.kill()
        // which drives its own teardown. In that case the errdefers in
        // this function must be skipped to avoid double-free.
        var skip_cleanup = false;
        errdefer if (!skip_cleanup) allocator.destroy(proc);

        proc.* = .{
            .pid = @atomicRmw(u64, &pid_counter, .Add, 1, .monotonic),
            .parent = parent,
            .alive = true,
            .restart_context = null,
            .addr_space_root = undefined,
            .vmm = undefined,
            .threads = undefined,
            .num_threads = 0,
            .children = undefined,
            .num_children = 0,
            .lock = .{},
            .perm_table = undefined,
            .perm_count = 0,
            .perm_lock = .{},
            .handle_counter = 1,
            .perm_view_vaddr = VAddr.fromInt(0),
            .perm_view_phys = PAddr.fromInt(0),
            .dma_mappings = undefined,
            .num_dma_mappings = 0,
            .fault_reason = .none,
            .restart_count = 0,
            .thread_handle_rights = thr_rights,
            .max_thread_priority = max_priority,
        };

        const pmm_iface = pmm.global_pmm.?.allocator();

        const pml4_page = try pmm_iface.create(paging.PageMem(.page4k));
        @memset(std.mem.asBytes(pml4_page), 0);

        const pml4_vaddr = VAddr.fromInt(@intFromPtr(pml4_page));
        proc.addr_space_root = PAddr.fromVAddr(pml4_vaddr, null);
        arch.copyKernelMappings(pml4_vaddr);

        const aslr_base = generateAslrBase();

        proc.vmm = VirtualMemoryManager.init(
            VAddr.fromInt(aslr_base),
            VAddr.fromInt(address.AddrSpacePartition.user.end),
            proc.addr_space_root,
        );
        // vmm.deinit() unmaps nodes and frees private phys pages; any pages
        // mapped without a vmm node (e.g. view_page before insertKernelNode)
        // are freed by freeUserAddrSpace below, which also frees the pml4.
        errdefer if (!skip_cleanup) proc.vmm.deinit();
        errdefer if (!skip_cleanup) arch.freeUserAddrSpace(proc.addr_space_root);

        const elf_result = try loadElf(proc, elf_binary, aslr_base);

        var view_page_mapped = false;
        const view_page = try pmm_iface.create(paging.PageMem(.page4k));
        errdefer if (!skip_cleanup and !view_page_mapped) pmm_iface.destroy(view_page);
        @memset(std.mem.asBytes(view_page), 0xFF);
        const view_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(view_page)), null);

        const view_vaddr = try proc.vmm.allocateAfterCursor(paging.PAGE4K);
        const view_perms = MemoryPerms{
            .write_perm = .no_write,
            .execute_perm = .no_execute,
            .cache_perm = .write_back,
            .global_perm = .not_global,
            .privilege_perm = .user,
        };
        try arch.mapPage(proc.addr_space_root, view_phys, view_vaddr, view_perms);
        // Once mapped, freeUserAddrSpace will reclaim view_page on error.
        view_page_mapped = true;
        try proc.vmm.insertKernelNode(view_vaddr, paging.PAGE4K, .{ .read = true }, .preserve);

        proc.perm_view_vaddr = view_vaddr;
        proc.perm_view_phys = view_phys;

        proc.initPermTable(initial_rights);

        if (initial_rights.restart) {
            proc.restart_context = try restart_context_mod.create(
                elf_result.entry,
                elf_result.data_vaddr,
                elf_result.data_content,
            );
        }
        errdefer if (!skip_cleanup) if (proc.restart_context) |rc| restart_context_mod.destroy(rc);

        const initial_thread = try thread_mod.Thread.create(proc, elf_result.entry, proc.perm_view_vaddr.addr, DEFAULT_STACK_PAGES);

        // Insert initial thread handle at slot 1
        proc.insertThreadHandleAtSlot(1, initial_thread, thr_rights);

        if (parent) |p| {
            p.lock.lock();
            defer p.lock.unlock();
            if (p.num_children >= MAX_CHILDREN) {
                // INVARIANT: `proc` has been allocated and its initial
                // thread created, but nothing outside this function
                // references it yet (no scheduler dispatch, no parent
                // children[] entry, no external handles). kill() runs
                // the full teardown path, which is safe here precisely
                // because of that invariant — no other CPU can observe
                // proc and there are no cross-process references to
                // reconcile. If future refactoring exposes `proc`
                // earlier (e.g. adding it to parent.children before
                // this check), this kill() call becomes incorrect; a
                // dedicated early-teardown helper should be factored
                // instead.
                skip_cleanup = true;
                proc.kill(.none);
                return error.TooManyChildren;
            }
            p.children[p.num_children] = proc;
            p.num_children += 1;
        }

        return proc;
    }

    pub fn createIdle() !*Process {
        const proc = try allocator.create(Process);
        proc.* = .{
            .pid = @atomicRmw(u64, &pid_counter, .Add, 1, .monotonic),
            .parent = null,
            .alive = true,
            .restart_context = null,
            .addr_space_root = memory_init.kernel_addr_space_root,
            .vmm = VirtualMemoryManager.init(
                VAddr.fromInt(address.AddrSpacePartition.user.start),
                VAddr.fromInt(address.AddrSpacePartition.user.end),
                memory_init.kernel_addr_space_root,
            ),
            .threads = undefined,
            .num_threads = 0,
            .children = undefined,
            .num_children = 0,
            .lock = .{},
            .perm_table = undefined,
            .perm_count = 0,
            .perm_lock = .{},
            .handle_counter = 1,
            .perm_view_vaddr = VAddr.fromInt(0),
            .perm_view_phys = PAddr.fromInt(0),
            .dma_mappings = undefined,
            .num_dma_mappings = 0,
            .fault_reason = .none,
            .restart_count = 0,
        };
        proc.initPermTable(.{});
        return proc;
    }
};

/// Remove `target` from `box` if it appears as the pending sender or in
/// the wait queue. Used during thread teardown to avoid leaving dangling
/// pointers in fault boxes.
fn scrubFromFaultBox(box: *MessageBox, target: *Thread) void {
    box.lock.lock();
    defer box.lock.unlock();
    if (box.isPendingReply() and box.pending_thread == target) {
        _ = box.endPendingReplyLocked();
    }
    _ = box.removeLocked(target);
}

/// Public entry point for scrubFromFaultBox so syscall.zig (sysThreadKill)
/// can perform the same cleanup the intra-process Process.kill() path does.
pub fn scrubFromFaultBoxPub(box: *MessageBox, target: *Thread) void {
    scrubFromFaultBox(box, target);
}

fn generateAslrBase() u64 {
    const aslr_start = address.UserVA.aslr.start;
    const aslr_end = address.UserVA.aslr.end;
    const aslr_range = aslr_end - aslr_start;
    const aslr_pages = aslr_range / paging.PAGE4K;
    const entropy = arch.readTimestamp();
    const offset_pages = entropy % (aslr_pages / 2);
    return aslr_start + offset_pages * paging.PAGE4K;
}

const ElfLoadResult = struct {
    entry: VAddr,
    data_vaddr: VAddr,
    data_content: []const u8,
};

// Maximum total mapped size for a single process ELF (64 MB).
const MAX_ELF_MAPPED_SIZE: u64 = 64 * 1024 * 1024;

fn loadElf(proc: *Process, elf_binary: []const u8, aslr_base: u64) !ElfLoadResult {
    if (elf_binary.len < @sizeOf(elf.Elf64_Ehdr)) return error.InvalidElf;

    const ehdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, elf_binary[0..@sizeOf(elf.Elf64_Ehdr)]);
    if (!std.mem.eql(u8, ehdr.e_ident[0..4], "\x7fELF")) return error.InvalidElf;
    if (ehdr.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) return error.InvalidElf;

    const phdr_offset = ehdr.e_phoff;
    const phdr_size = @as(u64, ehdr.e_phentsize);
    const phdr_count = @as(u64, ehdr.e_phnum);

    // Reject undersized program header entries — the kernel reads
    // @sizeOf(Elf64_Phdr) bytes at each offset, so the entry size
    // must be at least that large to prevent out-of-bounds reads.
    if (phdr_size < @sizeOf(elf.Elf64_Phdr)) return error.InvalidElf;

    const phdr_total = std.math.mul(u64, phdr_size, phdr_count) catch return error.InvalidElf;
    const phdr_end = std.math.add(u64, phdr_offset, phdr_total) catch return error.InvalidElf;
    if (phdr_end > elf_binary.len) return error.InvalidElf;

    const pmm_iface = pmm.global_pmm.?.allocator();
    const rela_info = findRelaSection(elf_binary, ehdr);

    var lowest_va: u64 = std.math.maxInt(u64);
    var highest_va: u64 = 0;
    var has_bss = false;
    var bss_start: u64 = 0;
    var bss_end: u64 = 0;

    var data_vaddr = VAddr.fromInt(0);
    var data_offset: u64 = 0;
    var data_filesz: u64 = 0;

    // Track PT_LOAD segments to detect overlaps.
    const MAX_LOAD_SEGMENTS = 8;
    var seg_ranges: [MAX_LOAD_SEGMENTS][2]u64 = undefined;
    var num_load_segments: usize = 0;

    var i: u64 = 0;
    while (i < phdr_count) : (i += 1) {
        const off = phdr_offset + i * phdr_size;
        const phdr = std.mem.bytesAsValue(elf.Elf64_Phdr, elf_binary[off..][0..@sizeOf(elf.Elf64_Phdr)]);
        if (phdr.p_type != elf.PT_LOAD) continue;

        // Use checked arithmetic for all segment address computations
        // to prevent overflow into kernel address space.
        const seg_start = std.math.add(u64, aslr_base, phdr.p_vaddr) catch return error.InvalidElf;
        const seg_file_end = std.math.add(u64, seg_start, phdr.p_filesz) catch return error.InvalidElf;
        const seg_mem_end = std.math.add(u64, seg_start, phdr.p_memsz) catch return error.InvalidElf;

        // All segment addresses must remain in user address space.
        if (!address.AddrSpacePartition.user.contains(seg_start)) return error.InvalidElf;
        if (seg_file_end > 0 and !address.AddrSpacePartition.user.contains(seg_file_end -| 1)) return error.InvalidElf;
        if (seg_mem_end > 0 and !address.AddrSpacePartition.user.contains(seg_mem_end -| 1)) return error.InvalidElf;

        // Reject overlapping PT_LOAD segments.
        if (num_load_segments >= MAX_LOAD_SEGMENTS) return error.InvalidElf;
        const page_aligned_start = std.mem.alignBackward(u64, seg_start, paging.PAGE4K);
        const page_aligned_end = std.mem.alignForward(u64, seg_mem_end, paging.PAGE4K);
        for (seg_ranges[0..num_load_segments]) |range| {
            if (page_aligned_start < range[1] and page_aligned_end > range[0]) return error.InvalidElf;
        }
        seg_ranges[num_load_segments] = .{ page_aligned_start, page_aligned_end };
        num_load_segments += 1;

        const writable = (phdr.p_flags & elf.PF_W) != 0;
        const executable = (phdr.p_flags & elf.PF_X) != 0;

        if (writable and !executable) {
            data_vaddr = VAddr.fromInt(seg_start);
            data_offset = phdr.p_offset;
            data_filesz = phdr.p_filesz;
        }

        if (seg_start < lowest_va) lowest_va = seg_start;
        if (seg_file_end > highest_va) highest_va = seg_file_end;

        if (phdr.p_memsz > phdr.p_filesz) {
            const this_bss_start = std.mem.alignForward(u64, seg_file_end, paging.PAGE4K);
            const this_bss_end = std.mem.alignForward(u64, seg_mem_end, paging.PAGE4K);
            if (this_bss_end > bss_end) bss_end = this_bss_end;
            if (!has_bss or this_bss_start < bss_start) bss_start = this_bss_start;
            has_bss = true;
        }
    }

    if (lowest_va >= highest_va and !has_bss) return error.InvalidElf;

    const page_start = std.mem.alignBackward(u64, lowest_va, paging.PAGE4K);
    const page_end = std.mem.alignForward(u64, highest_va, paging.PAGE4K);

    // Enforce a maximum on total mapped size to prevent memory exhaustion.
    const total_mapped = (page_end - page_start) + (if (has_bss and bss_end > bss_start) bss_end - bss_start else 0);
    if (total_mapped > MAX_ELF_MAPPED_SIZE) return error.InvalidElf;

    if (page_end > page_start) {
        try proc.vmm.insertKernelNode(
            VAddr.fromInt(page_start),
            page_end - page_start,
            .{ .read = true, .write = true, .execute = true },
            .preserve,
        );

        const load_perms = MemoryPerms{
            .write_perm = .write,
            .execute_perm = .execute,
            .cache_perm = .write_back,
            .global_perm = .not_global,
            .privilege_perm = .user,
        };

        var page_va = page_start;
        while (page_va < page_end) : (page_va += paging.PAGE4K) {
            const page = try pmm_iface.create(paging.PageMem(.page4k));
            @memset(std.mem.asBytes(page), 0);
            const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
            try arch.mapPage(proc.addr_space_root, phys, VAddr.fromInt(page_va), load_perms);
        }

        i = 0;
        while (i < phdr_count) : (i += 1) {
            const off = phdr_offset + i * phdr_size;
            const phdr = std.mem.bytesAsValue(elf.Elf64_Phdr, elf_binary[off..][0..@sizeOf(elf.Elf64_Phdr)]);
            if (phdr.p_type != elf.PT_LOAD) continue;
            if (phdr.p_filesz == 0) continue;

            const seg_vaddr = aslr_base + phdr.p_vaddr;
            if (phdr.p_offset + phdr.p_filesz > elf_binary.len) return error.InvalidElf;

            writeToUserPages(proc.addr_space_root, seg_vaddr, elf_binary[phdr.p_offset..][0..phdr.p_filesz]);
        }
    }

    if (has_bss and bss_end > bss_start) {
        try proc.vmm.insertKernelNode(
            VAddr.fromInt(bss_start),
            bss_end - bss_start,
            .{ .read = true, .write = true },
            .decommit,
        );
    }

    if (rela_info) |rela| {
        try applyRelocations(proc, aslr_base, elf_binary, rela.offset, rela.size);
    }

    const final_end = if (has_bss and bss_end > page_end) bss_end else page_end;
    proc.vmm.bump(VAddr.fromInt(final_end));

    const data_content: []const u8 = if (data_filesz > 0)
        elf_binary[data_offset..][0..data_filesz]
    else
        &[_]u8{};

    // Validate entry point lands in user address space.
    const entry_addr = std.math.add(u64, aslr_base, ehdr.e_entry) catch return error.InvalidElf;
    if (!address.AddrSpacePartition.user.contains(entry_addr)) return error.InvalidElf;

    return .{
        .entry = VAddr.fromInt(entry_addr),
        .data_vaddr = data_vaddr,
        .data_content = data_content,
    };
}

fn writeToUserPages(addr_space_root: PAddr, start_va: u64, data: []const u8) void {
    var offset: u64 = 0;
    while (offset < data.len) {
        const va = start_va + offset;
        const page_base = std.mem.alignBackward(u64, va, paging.PAGE4K);
        const page_offset = va - page_base;
        const paddr = arch.resolveVaddr(addr_space_root, VAddr.fromInt(page_base)) orelse return;
        const physmap_addr = VAddr.fromPAddr(paddr, null).addr + page_offset;
        const chunk_len = @min(data.len - offset, paging.PAGE4K - page_offset);
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        @memcpy(dst[0..chunk_len], data[offset..][0..chunk_len]);
        offset += chunk_len;
    }
}

const RelaInfo = struct {
    offset: u64,
    size: u64,
};

fn findRelaSection(elf_binary: []const u8, ehdr: *align(1) const elf.Elf64_Ehdr) ?RelaInfo {
    const shdr_offset = ehdr.e_shoff;
    const shdr_size = @as(u64, ehdr.e_shentsize);
    const shdr_count = @as(u64, ehdr.e_shnum);

    if (shdr_offset == 0 or shdr_count == 0) return null;

    // Reject undersized section header entries.
    if (shdr_size < @sizeOf(elf.Elf64_Shdr)) return null;

    // Use checked arithmetic to prevent overflow in bounds computation.
    const shdr_total = std.math.mul(u64, shdr_size, shdr_count) catch return null;
    const shdr_end = std.math.add(u64, shdr_offset, shdr_total) catch return null;
    if (shdr_end > elf_binary.len) return null;

    var s: u64 = 0;
    while (s < shdr_count) : (s += 1) {
        const off = shdr_offset + s * shdr_size;
        const shdr = std.mem.bytesAsValue(elf.Elf64_Shdr, elf_binary[off..][0..@sizeOf(elf.Elf64_Shdr)]);
        if (shdr.sh_type == elf.SHT_RELA) {
            return .{ .offset = shdr.sh_offset, .size = shdr.sh_size };
        }
    }
    return null;
}

fn applyRelocations(proc: *Process, aslr_base: u64, elf_binary: []const u8, rela_offset: u64, rela_size: u64) !void {
    const entry_size = @sizeOf(elf.Elf64_Rela);
    const num_entries = rela_size / entry_size;

    // Validate the entire rela table fits within the ELF binary.
    const rela_total = std.math.mul(u64, num_entries, entry_size) catch return error.InvalidElf;
    const rela_end = std.math.add(u64, rela_offset, rela_total) catch return error.InvalidElf;
    if (rela_end > elf_binary.len) return error.InvalidElf;

    var r: u64 = 0;
    while (r < num_entries) : (r += 1) {
        const off = rela_offset + r * entry_size;
        const rela = std.mem.bytesAsValue(elf.Elf64_Rela, elf_binary[off..][0..entry_size]);

        const rela_type = @as(u32, @truncate(rela.r_info));
        if (rela_type != @intFromEnum(elf.R_X86_64.RELATIVE)) continue;

        // Validate relocation target stays in user address space.
        const target_vaddr = std.math.add(u64, aslr_base, rela.r_offset) catch return error.InvalidElf;
        if (!address.AddrSpacePartition.user.contains(target_vaddr)) return error.InvalidElf;

        const value: u64 = @bitCast(@as(i64, rela.r_addend) +% @as(i64, @bitCast(aslr_base)));

        const page_base = std.mem.alignBackward(u64, target_vaddr, paging.PAGE4K);
        const paddr = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(page_base)) orelse return error.InvalidElf;
        const physmap_addr = VAddr.fromPAddr(paddr, null).addr + (target_vaddr - page_base);
        const ptr: *u64 = @ptrFromInt(physmap_addr);
        ptr.* = value;
    }
}

pub var allocator: std.mem.Allocator = undefined;
var pid_counter: u64 = 1;

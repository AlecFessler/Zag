const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const elf = std.elf;
const futex = zag.proc.futex;
const kprof = zag.kprof.trace_id;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;
const secure_slab = zag.memory.allocators.secure_slab;
const thread_mod = zag.sched.thread;

const ArchCpuContext = zag.arch.dispatch.cpu.ArchCpuContext;
const CrashReason = FaultReason;
const DeviceRegion = zag.memory.device_region.DeviceRegion;
const FaultReason = zag.perms.permissions.FaultReason;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const MessageBox = zag.proc.message_box.MessageBox;
const PAddr = zag.memory.address.PAddr;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const Priority = zag.sched.thread.Priority;
const ProcessRights = zag.perms.permissions.ProcessRights;
const RestartContext = zag.proc.restart_context.RestartContext;
const SharedMemory = zag.memory.shared.SharedMemory;
const SecureSlab = zag.memory.allocators.secure_slab.SecureSlab;
const SlabRef = zag.memory.allocators.secure_slab.SlabRef;
const SpinLock = zag.utils.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const ThreadHandleRights = zag.perms.permissions.ThreadHandleRights;
const UserViewEntry = zag.perms.permissions.UserViewEntry;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;

pub const DEFAULT_STACK_PAGES: u32 = 8;
pub const MAX_PERMS: usize = 128;
pub const MAX_DMA_MAPPINGS: usize = 16;
pub const HANDLE_SELF: u64 = 0;

/// `Process._gen_lock` ordered_group for cross-process fault-handling
/// paths.
///
/// `Process.faultBlock` (external-handler arm) holds the *handler*
/// process's `_gen_lock` across the stop-all walk that locks the
/// *faulting* process's own `_gen_lock`, and then dispatches to a
/// receiver Thread blocked in `fault_recv` (which acquires the
/// receiver's `Thread._gen_lock`).
///
/// Two distinct lockdep concerns this tag addresses:
///
///  1. Same-class overlap on `Process._gen_lock` — handler and self
///     are distinct Process instances. handler is always resolved
///     from `self.faultHandlerOf()`; the self-handling arm uses a
///     separate code path. The inner stop-all walk is bounded and
///     never blocks on userspace.
///
///  2. Cross-class edge insertion. With handler._gen_lock held we
///     subsequently lock a fault_recv waiter (`Thread._gen_lock`),
///     which would register a Process→Thread edge. `sysIpcReply`'s
///     cap-transfer path registers the inverse Thread→Process edge.
///     Neither pair is a real AB-BA at the instance level: handler
///     is a fault-handler Process and r_ref is its blocked recv
///     waiter; nothing in the kernel acquires these two specific
///     instances in the opposite order. Tagging the outer Process
///     acquire as ordered tells `debug_core.acquireOn` to skip the
///     pair-registry edge insertion for any acquisition while this
///     lock is held.
///
/// See `SpinLock.lockIrqSaveOrdered` and `kernel/proc/futex.zig`'s
/// `FUTEX_BUCKET_GROUP` for the prior art.
pub const FAULT_PROCESS_GENLOCK_GROUP: u32 = 1;

/// Build a `SlabRef(T)` from a live pointer by sampling the slot's
/// current gen. Callers use this at the moment they mint a handle
/// (insertPerm, etc.) — the captured gen becomes the staleness baseline
/// for every later `lock()` on the resulting ref. Must only be called
/// while the slot is live (gen is odd); the SlabRef constructor asserts.
pub fn slabRefNow(comptime T: type, ptr: *T) SlabRef(T) {
    return SlabRef(T).init(ptr, ptr._gen_lock.currentGen());
}

pub const DmaMapping = struct {
    device: SlabRef(DeviceRegion),
    shm: SlabRef(SharedMemory),
    dma_base: u64,
    num_pages: u64,
    active: bool,
};

pub const ProcessAllocator = SecureSlab(Process, 256);

pub const Process = struct {
    _gen_lock: secure_slab.GenLock = .{},
    pid: u64,
    parent: ?SlabRef(Process),
    alive: bool,
    restart_context: ?RestartContext,
    addr_space_root: PAddr,
    addr_space_id: u16,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]SlabRef(Thread),
    num_threads: u64,
    children: [MAX_CHILDREN]SlabRef(Process),
    num_children: u64,
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
    cleanup_complete: bool = false,
    /// True once cleanupPhase2 has run its teardown but the Process slab
    /// slot is deliberately preserved as a `dead_process` tombstone
    /// (§2.1.6: dead_process handles remain valid until explicit revoke).
    /// The slot holds no useful state beyond this flag — all resources
    /// are freed — but the slab slot + its live gen stay intact so the
    /// parent's perm-table entry continues to resolve.
    zombie: bool = false,
    fault_handler_proc: ?SlabRef(Process) = null,
    faulted_thread_slots: u64 = 0,
    suspended_thread_slots: u64 = 0,
    thread_handle_rights: ThreadHandleRights = ThreadHandleRights.full,
    max_thread_priority: Priority = .normal,
    // Back-pointer list of processes whose fault_handler_proc == self.
    // Walked on handler death to revert targets to self-handling (§2.12.35).
    // Protected by self.lock.
    fault_handler_targets_head: ?SlabRef(Process) = null,
    // Intrusive next-pointer for fault_handler_targets list of OUR handler.
    fault_handler_targets_next: ?SlabRef(Process) = null,
    // Whether slot 0's fault_handler bit was set at the moment the
    // relationship was established. releaseFaultHandler uses this to
    // decide whether restoring the bit is semantically valid — we never
    // want to synthesize a right the sender didn't have to begin with.
    had_self_fault_handler: bool = true,
    vm: ?SlabRef(arch.vm.Vm) = null,

    pub const MAX_THREADS = 64;
    pub const MAX_CHILDREN = 64;

    fn initPermTable(self: *Process, self_rights: ProcessRights) void {
        for (&self.perm_table) |*entry| {
            entry.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
        }
        self.perm_table[0] = .{
            .handle = HANDLE_SELF,
            .object = .{ .process = slabRefNow(Process, self) },
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

    /// Targeted sync for the hot insert/remove path: write only the
    /// slot that just changed, bump the generation counter, and wake
    /// any userspace waiters. Equivalent to `syncUserView` but O(1)
    /// instead of O(MAX_PERMS). Readers use the generation counter to
    /// detect racing updates and re-read any entries they care about,
    /// so a one-slot write produces a consistent view as long as the
    /// generation bump happens after the slot write and before the wake.
    fn syncUserViewSlot(self: *Process, slot_index: usize) void {
        if (self.perm_view_phys.addr == 0) return;
        const view_ptr: *[MAX_PERMS]UserViewEntry = @ptrFromInt(
            VAddr.fromPAddr(self.perm_view_phys, null).addr,
        );
        view_ptr[slot_index] = UserViewEntry.fromKernelEntry(self.perm_table[slot_index]);
        self.perm_view_gen += 1;
        // Generation lives in the self-entry (slot 0) regardless of which
        // slot changed, so writing it also overwrites anything fromKernelEntry
        // wrote into view_ptr[0].field1 when slot_index == 0.
        @atomicStore(u64, &view_ptr[0].field1, self.perm_view_gen, .release);
        const gen_paddr = PAddr.fromInt(self.perm_view_phys.addr + @offsetOf(UserViewEntry, "field1"));
        _ = futex.wake(gen_paddr, 0xFFFF_FFFF);
    }

    /// Insert a thread handle into this process's perm table.
    /// Returns the handle ID on success.
    pub fn insertThreadHandle(self: *Process, thread: *Thread, rights: ThreadHandleRights) !u64 {
        return self.insertPerm(.{
            .handle = 0,
            .object = .{ .thread = slabRefNow(Thread, thread) },
            .rights = @as(u16, @as(u8, @bitCast(rights))),
        });
    }

    /// Insert a thread handle at a specific slot (used for initial thread at slot 1).
    pub fn insertThreadHandleAtSlot(self: *Process, slot: usize, thread: *Thread, rights: ThreadHandleRights) void {
        self.perm_lock.lock(@src());
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
            .object = .{ .thread = slabRefNow(Thread, thread) },
            .rights = @as(u16, @as(u8, @bitCast(rights))),
        };
        self.perm_count += 1;
        self.syncUserView();
    }

    /// Remove all thread handles for a specific thread from this process's perm table.
    /// Clears every matching slot — there should only ever be one under the
    /// handle-table invariant ("each live thread has at most one perm slot
    /// per owning process"), but a stale duplicate from any future invariant
    /// break (see red-team Finding -3: self-cap-transfer fault_handler arm)
    /// would otherwise leave a dangling `*Thread` for `Thread.deinit` to
    /// hand back to the next syscall that takes a thread handle. Walking the
    /// whole table is O(MAX_PERMS) and thread exit is already not hot.
    pub fn removeThreadHandle(self: *Process, thread: *Thread) void {
        self.perm_lock.lock(@src());
        var drop: u32 = 0;
        for (&self.perm_table) |*slot| {
            if (slot.object == .thread and slot.object.thread.ptr == thread) {
                slot.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
                drop += 1;
            }
        }
        if (drop != 0) self.syncUserView();
        self.perm_lock.unlock();
    }

    /// Find the handle ID for a thread in this process's perm table.
    pub fn findThreadHandle(self: *Process, thread: *Thread) ?u64 {
        self.perm_lock.lock(@src());
        defer self.perm_lock.unlock();
        for (self.perm_table) |slot| {
            if (slot.object == .thread and slot.object.thread.ptr == thread) {
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
        self.perm_lock.lock(@src());
        for (&self.perm_table) |*slot| {
            // self-alive: iterating our own perm_table under perm_lock.
            // Identity compare — both .ptr accesses are analyzer-exempt
            // address reads, not derefs.
            if (slot.object == .thread and slot.object.thread.ptr.process.ptr == target) {
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
        target.perm_lock.lock(@src());
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
        self.fault_box.lock.lock(@src());
        if (self.fault_box.isPendingReply()) {
            if (self.fault_box.pending_thread) |pt_ref| {
                if (pt_ref.lock(@src())) |pt| {
                    const belongs = pt.process.ptr == target;
                    pt_ref.unlock();
                    if (belongs) {
                        _ = self.fault_box.endPendingReplyLocked();
                    }
                } else |_| {
                    // Pending thread's slot was freed; drop the stale entry.
                    _ = self.fault_box.endPendingReplyLocked();
                }
            }
        }
        self.fault_box.drainByProcessLocked(target);
        self.fault_box.lock.unlock();

        // §2.12.35: re-evaluate target's threads under self-handling.
        // - .suspended threads (from external stop-all) → .ready + enqueue.
        // - .faulted threads → push onto target's own fault_box so a sibling
        //   can recv them. Their state stays .faulted.
        // - If after re-eval no thread is alive (all .faulted), kill the
        //   process per §2.12.9.
        target._gen_lock.lock(@src());
        var resume_buf: [MAX_THREADS]SlabRef(Thread) = undefined;
        var resume_n: usize = 0;
        var faulted_buf: [MAX_THREADS]SlabRef(Thread) = undefined;
        var faulted_n: usize = 0;
        // self-alive: target._gen_lock is held, so removeThread can't run
        // on any of these siblings; their slab slots stay live for the
        // whole loop and we can read `.state` through `.ptr`.
        for (target.threads[0..target.num_threads]) |t_ref| {
            const t = t_ref.ptr;
            if (t.state == .suspended) {
                t.state = .ready;
                resume_buf[resume_n] = t_ref;
                resume_n += 1;
            } else if (t.state == .faulted) {
                faulted_buf[faulted_n] = t_ref;
                faulted_n += 1;
            }
        }
        target.suspended_thread_slots = 0;
        // Count alive threads (not .faulted, not .exited).
        // self-alive: same target._gen_lock window as the loop above.
        var alive: u64 = 0;
        for (target.threads[0..target.num_threads]) |t_ref| {
            const t = t_ref.ptr;
            if (t.state != .faulted and t.state != .exited) alive += 1;
        }
        target._gen_lock.unlock();

        for (resume_buf[0..resume_n]) |t_ref| {
            if (t_ref.lock(@src())) |t| {
                defer t_ref.unlock();
                const target_core = if (t.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
                sched.enqueueOnCore(target_core, t);
            } else |_| {}
        }

        if (alive == 0 and faulted_n > 0) {
            // No surviving thread to call fault_recv. §2.12.9: kill.
            target.kill(.killed);
        } else {
            // Push the faulted threads onto target's own fault_box.
            target.fault_box.lock.lock(@src());
            for (faulted_buf[0..faulted_n]) |t_ref| {
                const t = t_ref.lock(@src()) catch continue;
                defer t_ref.unlock();
                if (target.fault_box.isReceiving()) {
                    const r_ref = target.fault_box.takeReceiverLocked();
                    target.fault_box.beginPendingReplyLocked(t);
                    target.fault_box.lock.unlock();
                    if (r_ref.lock(@src())) |r| {
                        deliverFaultToWaiter(target, r, t);
                        r_ref.unlock();
                    } else |_| {
                        // Blocked receiver's slot was freed; drop the fault.
                    }
                    target.fault_box.lock.lock(@src());
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
        self._gen_lock.lock(@src());
        defer self._gen_lock.unlock();
        if (!self.alive) return false;
        // Avoid double-link. List nodes are SlabRef(Process); traversal
        // compares `.ptr` against `target` — the caller holds `target`
        // pinned (it's our own sender_proc context), so .ptr is live.
        var cur = self.fault_handler_targets_head;
        while (cur) |c_ref| {
            // self-alive: caller pins `target`; list nodes are siblings
            // of `target` whose own lifetimes are guarded by their
            // respective processes holding `self` as fault handler.
            if (c_ref.ptr == target) return true;
            cur = c_ref.ptr.fault_handler_targets_next;
        }
        target.fault_handler_targets_next = self.fault_handler_targets_head;
        self.fault_handler_targets_head = SlabRef(Process).init(target, target._gen_lock.currentGen());
        return true;
    }

    /// Unlink a target from this handler's fault_handler_targets list.
    pub fn unlinkFaultHandlerTarget(self: *Process, target: *Process) void {
        self._gen_lock.lock(@src());
        defer self._gen_lock.unlock();
        var prev: ?SlabRef(Process) = null;
        var cur = self.fault_handler_targets_head;
        while (cur) |c_ref| {
            // self-alive: caller pins `target`; other nodes are live
            // while linked (each holds `self` as its fault handler).
            if (c_ref.ptr == target) {
                if (prev) |p_ref| {
                    // self-alive: prev was just validated by the previous
                    // iteration and hasn't been unlinked since we hold
                    // self._gen_lock throughout.
                    p_ref.ptr.fault_handler_targets_next = c_ref.ptr.fault_handler_targets_next;
                } else {
                    self.fault_handler_targets_head = c_ref.ptr.fault_handler_targets_next;
                }
                target.fault_handler_targets_next = null;
                return;
            }
            prev = c_ref;
            cur = c_ref.ptr.fault_handler_targets_next;
        }
    }

    /// Materialize a FaultMessage for `faulted` and write it into the
    /// receiver process's user buffer at `buf_ptr` via physmap. Used by
    /// faultBlock direct-delivery: the receiver thread is blocked in
    /// sysFaultRecv and cannot itself dequeue + write on resume, so the
    /// sender (the faulting thread's kernel context) does it.
    fn writeFaultMessageInto(receiver_proc: *Process, buf_ptr: u64, process_handle: u64, thread_handle: u64, faulted: *Thread) void {
        // Layout matches libz.FaultMessage. Size is arch-dependent.
        var msg: [arch.cpu.fault_msg_size]u8 = undefined;
        @as(*align(1) u64, @ptrCast(&msg[0])).* = process_handle;
        @as(*align(1) u64, @ptrCast(&msg[8])).* = thread_handle;
        msg[16] = @intFromEnum(faulted.fault_reason);
        @memset(msg[17..24], 0);
        @as(*align(1) u64, @ptrCast(&msg[24])).* = faulted.fault_addr;
        @as(*align(1) u64, @ptrCast(&msg[32])).* = faulted.fault_rip;
        // Serialize the user-mode register frame from the fault's own
        // user context (which sysFaultReply also writes to for
        // FAULT_RESUME_MODIFIED). `faulted.ctx` is only guaranteed to
        // reflect user state on architectures where the exception frame
        // is written at a fixed per-thread kernel-stack slot; on aarch64
        // `yield()` nests another exception frame below the fault frame,
        // so `faulted.ctx` ends up pointing at the nested SGI frame
        // rather than the user fault frame. Using `fault_user_ctx`
        // directly — the same frame that `applyModifiedRegs` targets on
        // resume — keeps the delivered snapshot consistent across arches.
        const regs_src: *const arch.cpu.ArchCpuContext = faulted.fault_user_ctx orelse faulted.ctx;
        const snap = arch.cpu.serializeFaultRegs(regs_src);
        @as(*align(1) u64, @ptrCast(&msg[40])).* = snap.flags;
        @as(*align(1) u64, @ptrCast(&msg[48])).* = snap.sp;
        const gprs = snap.gprs;
        var off: usize = 56;
        for (gprs) |v| {
            @as(*align(1) u64, @ptrCast(&msg[off])).* = v;
            off += 8;
        }

        // Walk the receiver's page table and copy the message via physmap.
        var remaining: usize = arch.cpu.fault_msg_size;
        var src_off: usize = 0;
        var dst_va: u64 = buf_ptr;
        while (remaining > 0) {
            const page_off = dst_va & 0xFFF;
            const chunk = @min(remaining, paging.PAGE4K - page_off);
            const page_paddr = arch.paging.resolveVaddr(receiver_proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return;
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
        handler.perm_lock.lock(@src());
        defer handler.perm_lock.unlock();
        var proc_h: u64 = 0;
        var thread_h: u64 = 0;
        for (&handler.perm_table) |*slot| {
            switch (slot.object) {
                .thread => |r| if (r.ptr == faulted) {
                    thread_h = slot.handle;
                },
                // self-alive: `faulted` is owned by its caller for the
                // duration of fault delivery; its `.process` SlabRef
                // points at the live owning Process.
                .process => |r| if (r.ptr == faulted.process.ptr) {
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
        // is the first syscall argument (preserved from syscall entry).
        const buf_ptr = arch.syscall.getSyscallArgs(receiver.ctx).arg0;
        const handles = lookupHandlesForFault(handler, faulted);
        // self-alive: `receiver` is a live blocked thread owned by the
        // fault box; its owning process is alive while it's blocked.
        writeFaultMessageInto(receiver.process.ptr, buf_ptr, handles.proc_h, handles.thread_h, faulted);
        // Set the syscall return value: fault_recv returns the thread
        // handle (= the fault token) on success.
        arch.syscall.setSyscallReturn(receiver.ctx, handles.thread_h);
        wakeReceiver(receiver);
    }

    /// Wake a thread that was blocked on recv/fault_recv. Spins on
    /// `on_cpu` to make sure the thread is fully off-CPU before changing
    /// its state and re-enqueuing.
    fn wakeReceiver(t: *Thread) void {
        while (t.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
        t.state = .ready;
        const target_core = if (t.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
        sched.enqueueOnCore(target_core, t);
    }

    /// Resolve the process that should handle this process's faults.
    /// Returns null if no handler exists (caller must kill). Per
    /// `systems.md:876`, a process with `fault_handler_proc == null`
    /// self-handles iff it holds the `fault_handler` ProcessRight bit on
    /// slot 0; otherwise it has no handler at all.
    ///
    /// External handlers are returned as a `SlabRef(Process)` the caller
    /// must lock before touching. Self-handling is signaled by a null
    /// SlabRef and a true `is_self` flag — self is already pinned by
    /// virtue of being the faulting process, so no additional lock is
    /// needed.
    fn faultHandlerOf(self: *Process) ?struct { ref: ?SlabRef(Process), is_self: bool } {
        if (self.fault_handler_proc) |h| return .{ .ref = h, .is_self = false };
        if (self.perm_table[0].processRights().fault_handler) return .{ .ref = null, .is_self = true };
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
        const resolved = self.faultHandlerOf() orelse return false;

        // Stamp the fault payload onto the thread itself.
        thread.fault_reason = reason;
        thread.fault_addr = fault_addr;
        thread.fault_rip = rip;
        // Stash pointer to the user iret frame for FAULT_RESUME_MODIFIED.
        // Once the scheduler yields out of this thread, `thread.ctx` will
        // point at a kernel-mode context and no longer refers to the user
        // frame that the stub will iret through on resume.
        thread.fault_user_ctx = user_ctx;

        if (resolved.is_self) {
            // Self-handling: §2.12.7 / §2.12.8 / §2.12.9. No stop-all — sibling
            // threads continue running so they can call fault_recv on our own
            // fault box.
            self._gen_lock.lock(@src());
            // Count threads that are actually runnable and could call
            // fault_recv on our own box. §2.12.9 requires kill/restart if
            // there are no surviving receivers. `.exited` threads are gone,
            // `.suspended` threads cannot be scheduled, `.faulted` threads
            // are blocked awaiting their own handler — none of them can
            // service a fault. We include the currently-faulting thread
            // itself in `alive` (it hasn't been marked .faulted yet below),
            // so the check is `alive <= 1` (only us = no one else).
            var alive: u64 = 0;
            // self-alive: self._gen_lock held, threads[] entries can't be
            // freed (destroy would need proc lock via removeThread).
            for (self.threads[0..self.num_threads]) |t_ref| {
                const t = t_ref.ptr;
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
                self._gen_lock.unlock();
                return false;
            }
            thread.state = .faulted;
            self.faulted_thread_slots |= @as(u64, 1) << @intCast(thread.slot_index);
            self._gen_lock.unlock();

            // If a sibling is blocked on fault_recv, deliver directly into
            // its user buffer (the receiver cannot dequeue itself on
            // wake-up because the kernel doesn't restart sysFaultRecv).
            // Otherwise enqueue and let the next fault_recv pick it up.
            self.fault_box.lock.lock(@src());
            if (self.fault_box.isReceiving()) {
                const r_ref = self.fault_box.takeReceiverLocked();
                self.fault_box.beginPendingReplyLocked(thread);
                self.fault_box.lock.unlock();
                if (r_ref.lock(@src())) |r| {
                    deliverFaultToWaiter(self, r, thread);
                    r_ref.unlock();
                } else |_| {
                    // Receiver slot freed; fault is already in pending_reply,
                    // will be picked up on the next fault_recv.
                }
                return true;
            }
            self.fault_box.enqueueLocked(thread);
            self.fault_box.lock.unlock();
            return true;
        }

        // External handler path (§2.12.10): possibly stop-all + enqueue on
        // handler's box.
        const handler_ref = resolved.ref.?;
        // Tagged with FAULT_PROCESS_GENLOCK_GROUP: we hold this
        // across `self._gen_lock.lockOrdered` below so we can safely
        // walk handler.perm_table and self.threads[] in turn. Both
        // are Process._gen_lock instances on distinct processes.
        const handler = handler_ref.lockOrdered(FAULT_PROCESS_GENLOCK_GROUP, @src()) catch return false;
        defer handler_ref.unlock();
        //
        // §2.12.11: before stop-all, check the faulting thread's
        // exclude_oneshot / exclude_permanent flags on its perm entry in
        // the handler's table. If either is set, skip stop-all (only the
        // faulting thread enters .faulted). exclude_oneshot is consumed.
        var stop_all = true;
        handler.perm_lock.lock(@src());
        for (&handler.perm_table) |*slot| {
            if (slot.object == .thread and slot.object.thread.ptr == thread) {
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
        // We collect suspended siblings so we can remove them from run
        // queues and IPI their cores after releasing proc.lock.
        var stopped: [MAX_THREADS]?SlabRef(Thread) = .{null} ** MAX_THREADS;
        var stopped_count: u32 = 0;
        // Tagged with FAULT_PROCESS_GENLOCK_GROUP: handler._gen_lock
        // is held above. See the constant's doc comment for why this
        // same-class overlap is not an AB-BA risk.
        self._gen_lock.lockOrdered(FAULT_PROCESS_GENLOCK_GROUP, @src());
        if (stop_all) {
            // self-alive: self._gen_lock held, siblings can't be freed.
            for (self.threads[0..self.num_threads]) |sib_ref| {
                const sib = sib_ref.ptr;
                if (sib == thread) continue;
                if (sib.state == .ready or sib.state == .running) {
                    sib.state = .suspended;
                    self.suspended_thread_slots |= @as(u64, 1) << @intCast(sib.slot_index);
                    stopped[stopped_count] = sib_ref;
                    stopped_count += 1;
                }
            }
        }
        thread.state = .faulted;
        self.faulted_thread_slots |= @as(u64, 1) << @intCast(thread.slot_index);
        self._gen_lock.unlock();

        // Force-deschedule stopped siblings: remove from run queues
        // (in case they were .ready) and IPI cores where they are
        // dispatched (in case they were .running or raced to .running).
        for (stopped[0..stopped_count]) |maybe_sib_ref| {
            const sib_ref = maybe_sib_ref orelse continue;
            const sib = sib_ref.lock(@src()) catch continue;
            defer sib_ref.unlock();
            sched.removeFromAnyRunQueue(sib);
            if (sched.coreRunning(sib)) |core_id| {
                arch.smp.triggerSchedulerInterrupt(core_id);
            }
        }

        handler.fault_box.lock.lock(@src());
        if (handler.fault_box.isReceiving()) {
            const r_ref = handler.fault_box.takeReceiverLocked();
            handler.fault_box.beginPendingReplyLocked(thread);
            handler.fault_box.lock.unlock();
            if (r_ref.lock(@src())) |r| {
                deliverFaultToWaiter(handler, r, thread);
                r_ref.unlock();
            } else |_| {
                // Receiver slot freed; fault is already in pending_reply,
                // will be picked up on the next fault_recv.
            }
        } else {
            handler.fault_box.enqueueLocked(thread);
            handler.fault_box.lock.unlock();
        }

        return true;
    }

    pub fn getPermByHandle(self: *Process, handle_id: u64) ?PermissionEntry {
        self.perm_lock.lock(@src());
        defer self.perm_lock.unlock();
        return self.getPermByHandleLocked(handle_id);
    }

    /// Look up a handle that references a thread. Returns the permission
    /// entry snapshot plus a `SlabRef(Thread)` the caller can lock; null
    /// on handle-not-found or when the entry is not a thread.
    ///
    /// The returned `SlabRef` carries the gen captured when the handle
    /// was issued. A concurrent Thread.deinit that frees the slot on
    /// another core will bump the gen, so the next `thread_ref.lock()`
    /// on this caller side fails with `StaleHandle` rather than
    /// silently touching a recycled slot. Callers that deref the
    /// pointer across a yield / blocking call / fn return should
    /// acquire the lock via `thread_ref.lock()` for UAF safety.
    pub fn lookupThreadHandle(self: *Process, handle_id: u64) ?struct {
        entry: PermissionEntry,
        thread: SlabRef(Thread),
    } {
        self.perm_lock.lock(@src());
        defer self.perm_lock.unlock();
        const entry = self.getPermByHandleLocked(handle_id) orelse return null;
        if (entry.object != .thread) return null;
        return .{ .entry = entry, .thread = entry.object.thread };
    }

    /// Look up a handle while the caller already holds perm_lock.
    /// Stale-gen entries are reported as missing: the backing SecureSlab
    /// slot has been freed (and possibly reallocated) since the handle
    /// was issued, so the `*T` in the entry no longer refers to the
    /// object the caller thinks it does.
    pub fn getPermByHandleLocked(self: *const Process, handle_id: u64) ?PermissionEntry {
        for (self.perm_table) |entry| {
            if (entry.object == .empty or entry.handle != handle_id) continue;
            if (!entry.object.isFresh()) return null;
            return entry;
        }
        return null;
    }

    pub fn insertPerm(self: *Process, entry_in: PermissionEntry) !u64 {
        self.perm_lock.lock(@src());
        defer self.perm_lock.unlock();
        for (self.perm_table[1..], 1..) |*slot, slot_index| {
            if (slot.object == .empty) {
                const handle_id = self.handle_counter;
                self.handle_counter += 1;
                slot.* = entry_in;
                slot.handle = handle_id;
                self.perm_count += 1;
                self.syncUserViewSlot(slot_index);
                return handle_id;
            }
        }
        return error.PermTableFull;
    }

    pub fn removePerm(self: *Process, handle_id: u64) !void {
        if (handle_id == HANDLE_SELF) return error.CannotRevokeSelf;
        self.perm_lock.lock(@src());
        for (self.perm_table[1..], 1..) |*slot, slot_index| {
            if (slot.object != .empty and slot.handle == handle_id) {
                slot.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
                self.syncUserViewSlot(slot_index);
                self.perm_lock.unlock();
                return;
            }
        }
        self.perm_lock.unlock();
        return error.NotFound;
    }

    pub fn removeChild(self: *Process, child: *Process) void {
        self._gen_lock.lock(@src());
        defer self._gen_lock.unlock();
        for (self.children[0..self.num_children], 0..) |c_ref, i| {
            // self-alive: children array entries are live while occupied —
            // a child's cleanupPhase2 is what drives this call, so `child`
            // itself is the caller context. We compare `.ptr` for identity.
            if (c_ref.ptr == child) {
                self.num_children -= 1;
                if (i < self.num_children) {
                    self.children[i] = self.children[self.num_children];
                }
                return;
            }
        }
    }

    pub fn removeThread(self: *Process, thread: *Thread) bool {
        self._gen_lock.lock(@src());
        defer self._gen_lock.unlock();
        // self-alive: self._gen_lock held, threads[] entries are stable.
        // `.ptr == thread` is identity compare — `thread` is the caller's
        // live `*Thread` (we're in its deinit path).
        for (self.threads[0..self.num_threads], 0..) |t_ref, i| {
            if (t_ref.ptr == thread) {
                self.num_threads -= 1;
                if (i < self.num_threads) {
                    self.threads[i] = self.threads[self.num_threads];
                    self.threads[i].ptr.slot_index = @intCast(i);
                }
                return self.num_threads == 0;
            }
        }
        unreachable;
    }

    pub fn kill(self: *Process, reason: CrashReason) void {
        self._gen_lock.lock(@src());
        if (!self.alive) {
            self._gen_lock.unlock();
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
        var blocked: [MAX_THREADS]SlabRef(Thread) = undefined;
        var num_blocked: u32 = 0;
        // self-alive: self._gen_lock held — threads[] entries stable.
        for (self.threads[0..self.num_threads]) |t_ref| {
            const thread = t_ref.ptr;
            if (thread.state == .blocked or thread.state == .faulted or thread.state == .suspended) {
                blocked[num_blocked] = t_ref;
                num_blocked += 1;
            }
            thread.state = .exited;
        }
        self.faulted_thread_slots = 0;
        self.suspended_thread_slots = 0;
        self._gen_lock.unlock();

        // Remove blocked threads from external wait structures and deinit them.
        // Each deinit calls removeThread which decrements num_threads.
        // The last thread's deinit triggers lastThreadExited.
        // self-alive: blocked[] was snapshotted under self._gen_lock, and
        // the only path that frees these slots is Thread.deinit() which
        // this loop drives serially. No concurrent reaper can race.
        for (blocked[0..num_blocked]) |thread_ref| {
            const thread = thread_ref.ptr;
            // Wait until the thread is fully off-CPU before freeing its
            // kernel stack. .suspended and .faulted threads may still be in
            // the middle of a syscall on their kernel stack.
            while (thread.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            // A thread that was .ready when stop-all marked it .suspended is
            // still linked into a per-core run queue. Remove it before
            // deinit, otherwise the dangling pointer in the queue is a UAF
            // waiting to happen on the next dequeue.
            sched.removeFromAnyRunQueue(thread);
            if (thread.futex_bucket_count > 0) {
                futex.removeBlockedThread(thread);
            }
            if (thread.ipc_server) |server_ref| {
                // self-alive: kill() is tearing down all threads of `self`
                // and holds no external lock; the server pointer is the
                // ipc_server we ourselves stored and must outlive the
                // reply-wait state we're now draining.
                const server = server_ref.ptr;
                server.msg_box.lock.lock(@src());
                if (server.msg_box.isPendingReply() and
                    server.msg_box.pending_thread != null and
                    server.msg_box.pending_thread.?.ptr == thread)
                {
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
            if (self.fault_handler_proc) |handler_ref| {
                if (handler_ref.lock(@src())) |handler| {
                    defer handler_ref.unlock();
                    scrubFromFaultBox(&handler.fault_box, thread);
                } else |_| {}
            }
            thread.deinit(@intCast(thread_ref.gen));
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
        while (i < self.num_children) {
            const child_ref = self.children[i];
            if (child_ref.lock(@src())) |child| {
                // Release the lock before recursing — killSubtree re-enters
                // on the child and will take its own _gen_lock.
                child_ref.unlock();
                child.killSubtree();
            } else |_| {}
            i += 1;
        }
        self.kill(.killed);
    }

    pub fn disableRestart(self: *Process) void {
        self._gen_lock.lock(@src());
        if (self.restart_context) |*rc| {
            rc.deinit();
            self.restart_context = null;
        }
        self._gen_lock.unlock();

        // §2.3.4: clear the restart bit from slot 0 of our own permission
        // table and publish to the user view so userspace observes that the
        // capability is gone.
        self.perm_lock.lock(@src());
        var self_rights = self.perm_table[0].processRights();
        self_rights.restart = false;
        self.perm_table[0].rights = @bitCast(self_rights);
        self.syncUserView();
        self.perm_lock.unlock();

        var i: u64 = 0;
        while (i < self.num_children) {
            const child_ref = self.children[i];
            if (child_ref.lock(@src())) |child| {
                child_ref.unlock();
                child.disableRestart();
            } else |_| {}
            i += 1;
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
        self._gen_lock.lock(@src());
        if (!self.alive) {
            self._gen_lock.unlock();
            return;
        }
        if (self.fault_reason == .none) {
            self.fault_reason = .normal_exit;
        }
        const should_restart = self.restart_context != null;
        if (!should_restart) {
            self.alive = false;
        }
        self._gen_lock.unlock();

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
            if (self.parent) |parent_ref| {
                if (parent_ref.lock(@src())) |p| {
                    defer parent_ref.unlock();
                    p.convertToDeadProcess(self);
                } else |_| {}
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
        self.msg_box.lock.lock(@src());
        const restored_caller_ref: ?SlabRef(Thread) = if (self.msg_box.isPendingReply())
            self.msg_box.endPendingReplyLocked()
        else
            null;
        if (restored_caller_ref) |cr| {
            if (cr.lock(@src())) |pc| {
                self.msg_box.enqueueFrontLocked(pc);
                cr.unlock();
            } else |_| {
                // Caller slot was freed since pending_reply registration;
                // nothing to re-enqueue.
            }
        }
        if (self.msg_box.isReceiving()) {
            _ = self.msg_box.takeReceiverLocked();
        }
        self.msg_box.lock.unlock();

        self.vmm.resetForRestart();

        // Clean up thread handles from own perm table and handler's perm table
        if (self.fault_handler_proc) |handler_ref| {
            if (handler_ref.lock(@src())) |handler| {
                defer handler_ref.unlock();
                handler.perm_lock.lock(@src());
                for (&handler.perm_table) |*slot| {
                    // self-alive: walking handler's perm_table under perm_lock.
                    // Identity compare — .ptr accesses are analyzer-exempt.
                    if (slot.object == .thread and slot.object.thread.ptr.process.ptr == self) {
                        slot.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                        handler.perm_count -= 1;
                    }
                }
                handler.syncUserView();
                handler.perm_lock.unlock();

                // §2.6.35: also drain the handler's fault_box of any entries
                // pointing at our threads. The threads have already been
                // deinit'd by the kill() path, so the queue holds dangling
                // pointers — must scrub before the handler can recv again.
                handler.fault_box.lock.lock(@src());
                if (handler.fault_box.isPendingReply()) {
                    if (handler.fault_box.pending_thread) |pt_ref| {
                        if (pt_ref.lock(@src())) |pt| {
                            const belongs = pt.process.ptr == self;
                            pt_ref.unlock();
                            if (belongs) {
                                _ = handler.fault_box.endPendingReplyLocked();
                            }
                        } else |_| {
                            // Pending thread's slot was freed; drop the stale entry.
                            _ = handler.fault_box.endPendingReplyLocked();
                        }
                    }
                }
                handler.fault_box.drainByProcessLocked(self);
                handler.fault_box.lock.unlock();
            } else |_| {}
        }

        // Drain our own fault_box too — when self-handling, queued faulting
        // threads are our own dead threads.
        self.fault_box.lock.lock(@src());
        if (self.fault_box.isPendingReply()) {
            _ = self.fault_box.endPendingReplyLocked();
        }
        if (self.fault_box.isReceiving()) {
            _ = self.fault_box.takeReceiverLocked();
        }
        while (self.fault_box.dequeueLocked()) |_| {}
        self.fault_box.lock.unlock();

        // Snapshot thread-entry refs under perm_lock WITHOUT taking each
        // thread's gen-lock: the `perm_lock → Thread._gen_lock` edge
        // closes a 3-class cycle with the `Thread._gen_lock →
        // Process._gen_lock → Process.perm_lock` edges established by
        // the PMU syscalls / transferCapability. Break the cycle by
        // deferring per-thread work until after perm_lock is dropped.
        // The snapshot is bounded by the static `MAX_PERMS` table size
        // — it cannot grow past the set we iterate here.
        var thread_snapshot: [MAX_PERMS]SlabRef(Thread) = undefined;
        var snapshot_len: usize = 0;
        self.perm_lock.lock(@src());
        for (&self.perm_table) |*entry| {
            if (entry.object == .vm_reservation) {
                entry.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
            } else if (entry.object == .thread) {
                thread_snapshot[snapshot_len] = entry.object.thread;
                snapshot_len += 1;
                entry.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
            }
        }
        self.faulted_thread_slots = 0;
        self.suspended_thread_slots = 0;
        self.syncUserView();
        self.perm_lock.unlock();

        // Process the snapshot after releasing perm_lock. Take each
        // thread's gen-lock individually to read priority / affinity —
        // a stale ref (freed since the snapshot) is a benign no-op.
        for (thread_snapshot[0..snapshot_len]) |thread_ref| {
            if (thread_ref.lock(@src())) |t| {
                defer thread_ref.unlock();
                if (t.priority == .pinned) {
                    const core_id = @ctz(t.core_affinity orelse 0);
                    sched.unpinByRevoke(core_id);
                }
            } else |_| {}
        }

        self.updateParentView();

        if (rc.data_size > 0) {
            writeToUserPages(
                self.addr_space_root,
                rc.data_vaddr.addr,
                rc.ghostSlice(),
            );

            // Zero partial-page BSS: the bytes between the end of initialized data
            // and the next page boundary are BSS that lives on the same page as the
            // data segment tail. The .decommit node only covers full BSS pages;
            // this partial page is in the .preserve node and must be zeroed explicitly.
            const data_end = rc.data_vaddr.addr + rc.data_size;
            const next_page = std.mem.alignForward(u64, data_end, paging.PAGE4K);
            const tail_len = next_page - data_end;
            if (tail_len > 0 and tail_len < paging.PAGE4K) {
                const page_base = std.mem.alignBackward(u64, data_end, paging.PAGE4K);
                const page_offset = data_end - page_base;
                if (arch.paging.resolveVaddr(self.addr_space_root, VAddr.fromInt(page_base))) |paddr| {
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
        if (self.fault_handler_proc) |handler_ref| {
            // Verify handler freshness, then drop the gen-lock bit so the
            // downstream calls (which themselves take handler locks) don't
            // deadlock. The fault_handler relationship keeps handler linked
            // to us via fault_handler_targets — handler's cleanupPhase1
            // unlinks under self._gen_lock before freeing — so the window
            // between verify and call is bounded by handler-cleanup order.
            if (handler_ref.lock(@src())) |handler| {
                handler_ref.unlock();
                if (handler.insertThreadHandle(thread, ThreadHandleRights.full)) |_| {
                    // OK
                } else |_| {
                    handler.releaseFaultHandler(self);
                }
            } else |_| {}
        }

        // Spread restart placement away from the calling core. The
        // exit → performRestart cycle runs in scheduler context (the
        // outgoing thread's deinit at sched.handlePreemption); pinning
        // the new thread on the calling core lets a fast restart loop
        // starve everything else queued there. See `sched.pickRestartCore`.
        const target_core = sched.pickRestartCore(thread, arch.smp.coreID());
        sched.enqueueOnCore(target_core, thread);
    }

    fn updateParentView(self: *Process) void {
        const parent_ref = self.parent orelse return;
        const parent = parent_ref.lock(@src()) catch {
            return;
        };
        defer parent_ref.unlock();
        parent.perm_lock.lock(@src());
        defer parent.perm_lock.unlock();
        for (parent.perm_table[1..], 1..) |*slot, idx| {
            const matches = switch (slot.object) {
                .process => |r| r.ptr == self,
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
        self.msg_box.lock.lock(@src());

        // Drain all queued waiters with E_NOENT.
        while (self.msg_box.dequeueLocked()) |w| {
            w.ipc_server = null;
            arch.syscall.setSyscallReturn(w.ctx, @bitCast(@as(i64, -10)));
            while (w.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            w.state = .ready;
            const target_core = if (w.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
            sched.enqueueOnCore(target_core, w);
        }

        // Unblock the pending caller (delivered but not replied) if any.
        if (self.msg_box.isPendingReply()) {
            if (self.msg_box.endPendingReplyLocked()) |pc_ref| {
                if (pc_ref.lock(@src())) |pc| {
                    pc.ipc_server = null;
                    arch.syscall.setSyscallReturn(pc.ctx, @bitCast(@as(i64, -10)));
                    while (pc.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
                    pc.state = .ready;
                    const target_core = if (pc.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.smp.coreID();
                    sched.enqueueOnCore(target_core, pc);
                    pc_ref.unlock();
                } else |_| {
                    // Caller slot was freed; nothing to unblock.
                }
            }
        }

        // Drop the receiver (its thread is dead too — we're tearing down).
        if (self.msg_box.isReceiving()) {
            _ = self.msg_box.takeReceiverLocked();
        }

        self.msg_box.lock.unlock();

        // Clean up threads that are blocked waiting for reply from other processes
        // self-alive: cleanupPhase1 runs under process death, no concurrent
        // thread creation/destruction races us — threads[] entries are stable.
        for (self.threads[0..self.num_threads]) |t_ref| {
            const thread = t_ref.ptr;
            if (thread.ipc_server) |server_ref| {
                // self-alive: same rationale as the kill() branch — we
                // ourselves stored this ipc_server, and it outlives the
                // reply state we're draining.
                const server = server_ref.ptr;
                server.msg_box.lock.lock(@src());
                if (server.msg_box.isPendingReply() and
                    server.msg_box.pending_thread != null and
                    server.msg_box.pending_thread.?.ptr == thread)
                {
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
            self._gen_lock.lock(@src());
            const target_ref_opt = self.fault_handler_targets_head;
            self._gen_lock.unlock();
            const target_ref = target_ref_opt orelse break;
            // releaseFaultHandler unlinks t from our list, so loop terminates.
            // The target is linked into our list because we're its fault
            // handler; the list's own invariant keeps the target's slab
            // slot alive. Use `.ptr` under that linkage invariant.
            // self-alive: fault_handler_targets list entries are alive
            // while we haven't released them — target's death unlinks
            // itself before freeing.
            const t = target_ref.ptr;
            self.releaseFaultHandler(t);
        }

        // If we have an external fault handler, unlink ourselves from its
        // list and drain any of our threads from its fault box. We don't
        // call releaseFaultHandler on the handler because that would touch
        // our own perm table while we're in the middle of cleanup.
        if (self.fault_handler_proc) |handler_ref| {
            if (handler_ref.lock(@src())) |handler| {
                // Drop the gen-lock bit before calling handler methods
                // that take their own locks (unlinkFaultHandlerTarget
                // takes handler._gen_lock).
                handler_ref.unlock();
                handler.unlinkFaultHandlerTarget(self);
                handler.fault_box.lock.lock(@src());
                // Drop pending_thread if it points at one of ours.
                if (handler.fault_box.isPendingReply()) {
                    if (handler.fault_box.pending_thread) |pt_ref| {
                        if (pt_ref.lock(@src())) |pt| {
                            const belongs = pt.process.ptr == self;
                            pt_ref.unlock();
                            if (belongs) {
                                _ = handler.fault_box.endPendingReplyLocked();
                            }
                        } else |_| {
                            // Pending thread's slot was freed; drop the stale entry.
                            _ = handler.fault_box.endPendingReplyLocked();
                        }
                    }
                }
                // Drain any of our queued threads from the handler's box.
                handler.fault_box.drainByProcessLocked(self);
                handler.fault_box.lock.unlock();
            } else |_| {}
            self.fault_handler_proc = null;
        }

        if (self.vm) |vm_ref| {
            // self-alive: self is being torn down; no other observer
            // can race destroy of our own VM.
            vm_ref.ptr.destroy(@intCast(vm_ref.gen));
            self.vm = null;
        }

        self.cleanupIpcState();
        self.cleanupDmaMappings();
        self.vmm.deinit();

        // Drop perm-table entries. SharedMemory still has its own refcount
        // (it manages backing pages, not slot lifetime); everything else
        // has no lifetime bookkeeping on this path.
        for (self.perm_table[1..]) |*entry| {
            switch (entry.object) {
                .shared_memory => |r| r.ptr.decRef(),
                .device_region => |r| {
                    returnDeviceHandleUpTree(self, entry.rights, r.ptr);
                },
                .thread => |r| {
                    const t = r.ptr;
                    if (t.priority == .pinned) {
                        const core_id = @ctz(t.core_affinity orelse 0);
                        sched.unpinByRevoke(core_id);
                    }
                },
                .vm, .process, .dead_process, .vm_reservation, .empty => {},
            }
            entry.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
        }
        self.perm_table[0] = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };

        arch.paging.freeUserAddrSpace(self.addr_space_root);
        if (self.addr_space_id != 0) {
            arch.paging.freeAddrSpaceId(self.addr_space_id);
            self.addr_space_id = 0;
        }
    }

    fn cleanupPhase2(self: *Process) void {
        if (self.parent) |parent_ref| {
            if (parent_ref.lock(@src())) |p| {
                // Drop the gen-lock bit — removeChild / cleanupPhase2 both
                // take parent._gen_lock themselves. We only used the lock
                // here to verify parent's slab slot hasn't been recycled.
                parent_ref.unlock();
                p.removeChild(self);
                p.convertToDeadProcess(self);

                if (!p.alive and p.num_children == 0) {
                    p.cleanupPhase2();
                }
            } else |_| {}
        }

        if (self.restart_context) |*rc| rc.deinit();

        self.cleanup_complete = true;
        // Keep the slab slot alive as a dead_process tombstone. Any handle
        // to this Process (parent's .dead_process entry, IPC-transferred
        // handles) continues to resolve; the gen stays odd/live. The slot
        // is leaked for now — a handle-counting scheme or GC sweep can
        // reclaim it later. Correctness first, reclamation later.
        @atomicStore(bool, &self.zombie, true, .release);
    }

    /// Convert a live `process` entry in `holder`'s perm table to
    /// `dead_process`. Called from doExit (zombie path) and cleanupPhase2
    /// (leaf path), and also lazily from IPC paths when a send/call
    /// discovers the target is dead.
    /// Convert ALL live `process` entries for `child` in `holder`'s perm
    /// table to `dead_process`. A holder can have multiple handles to the
    /// same child (e.g. one from proc_create, another from cap transfer).
    pub fn convertToDeadProcess(holder: *Process, child: *Process) void {
        holder.perm_lock.lock(@src());
        defer holder.perm_lock.unlock();
        var converted = false;
        for (holder.perm_table[1..], 1..) |*slot, idx| {
            const matches = switch (slot.object) {
                .process => |r| r.ptr == child,
                else => false,
            };
            if (matches) {
                // Carry the original .process SlabRef's gen over to the
                // dead_process variant: the slab slot is the same Process
                // and has not been freed, so the handle stays fresh for
                // the tombstone lifetime (§2.1.6). Hoist the RHS into a
                // local to avoid Zig result-location-semantics: writing
                // the new union tag in place would change slot.object's
                // active tag to .dead_process before the RHS read of
                // slot.object.process, tripping the inactive-field
                // safety check.
                const old_ref = slot.object.process;
                slot.object = .{ .dead_process = old_ref };
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
            .device = slabRefNow(DeviceRegion, device),
            .shm = slabRefNow(SharedMemory, shm),
            .dma_base = dma_base,
            .num_pages = num_pages,
            .active = true,
        };
        self.num_dma_mappings += 1;
    }

    pub fn removeDmaMapping(self: *Process, device: *DeviceRegion, shm: *SharedMemory) ?DmaMapping {
        for (self.dma_mappings[0..self.num_dma_mappings], 0..) |*m, i| {
            // Identity compares don't deref — `.ptr` here is a raw pointer
            // equality check, which the analyzer exempts.
            if (m.active and m.device.ptr == device and m.shm.ptr == shm) {
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
                // Process teardown holds the only reference to these
                // mappings; the device slot is pinned by the parent's
                // perm table (the handle gets returned up-tree in
                // cleanupPhase1's walk, which runs after this function).
                // self-alive: teardown path, device slot pinned above.
                arch.iommu.unmapDmaPages(m.device.ptr, m.dma_base, m.num_pages);
                m.active = false;
            }
        }
        self.num_dma_mappings = 0;
    }

    pub fn returnDeviceHandleUpTree(source: *Process, rights: u16, device: *DeviceRegion) void {
        var ancestor = source.parent;
        while (ancestor) |anc_ref| {
            const anc = anc_ref.lock(@src()) catch break;
            const next = anc.parent;
            if (anc.alive) {
                if (anc.insertPerm(.{
                    .handle = 0,
                    .object = .{ .device_region = slabRefNow(DeviceRegion, device) },
                    .rights = rights,
                })) |_| {
                    anc_ref.unlock();
                    return;
                } else |_| {
                    // Table full — continue walk to next ancestor (§2.1.11).
                }
            }
            anc_ref.unlock();
            ancestor = next;
        }
    }

    pub fn create(elf_binary: []const u8, initial_rights: ProcessRights, parent: ?*Process, thr_rights: ThreadHandleRights, max_priority: Priority) !*Process {
        const proc_alloc = try slab_instance.create();
        const proc = proc_alloc.ptr;
        // The late-stage TooManyChildren branch below calls proc.kill()
        // which drives its own teardown. In that case the errdefers in
        // this function must be skipped to avoid double-free.
        var skip_cleanup = false;
        errdefer if (!skip_cleanup) slab_instance.destroy(proc, proc_alloc.gen) catch unreachable;

        // Field-by-field init preserves `proc._gen_lock`, which the slab
        // allocator just set to the freshly-advanced live gen. A whole-
        // struct `proc.* = .{...}` would zero it.
        proc.pid = @atomicRmw(u64, &pid_counter, .Add, 1, .monotonic);
        proc.parent = if (parent) |p| slabRefNow(Process, p) else null;
        proc.alive = true;
        proc.restart_context = null;
        proc.addr_space_root = undefined;
        proc.addr_space_id = 0;
        proc.vmm = undefined;
        proc.threads = undefined;
        proc.num_threads = 0;
        proc.children = undefined;
        proc.num_children = 0;
        proc.perm_table = undefined;
        proc.perm_count = 0;
        proc.perm_lock = .{ .class = "Process.perm_lock" };
        proc.handle_counter = 1;
        proc.perm_view_vaddr = VAddr.fromInt(0);
        proc.perm_view_phys = PAddr.fromInt(0);
        proc.dma_mappings = undefined;
        proc.num_dma_mappings = 0;
        proc.msg_box = .{};
        proc.fault_box = .{};
        // Override class strings so lockdep treats `msg_box.lock` and
        // `fault_box.lock` as distinct classes. They never alias (one
        // serves IPC, the other fault delivery) and routinely appear
        // in opposite orderings against `Process._gen_lock`:
        //   * sysIpcReply: msg_box.lock → Process._gen_lock (ipc.zig:151)
        //   * faultBlock:  Process._gen_lock → fault_box.lock (process.zig:712)
        // Without per-instance class identity these would register as
        // an AB-BA cycle even though no single instance can be on both
        // sides of the cycle.
        proc.msg_box.lock.class = "MessageBox.msg_box.lock";
        proc.fault_box.lock.class = "MessageBox.fault_box.lock";
        proc.fault_reason = .none;
        proc.restart_count = 0;
        proc.perm_view_gen = 0;
        proc.cleanup_complete = false;
        proc.fault_handler_proc = null;
        proc.faulted_thread_slots = 0;
        proc.suspended_thread_slots = 0;
        proc.thread_handle_rights = thr_rights;
        proc.max_thread_priority = max_priority;
        proc.fault_handler_targets_head = null;
        proc.fault_handler_targets_next = null;
        proc.had_self_fault_handler = true;
        proc.vm = null;

        const pmm_mgr = &pmm.global_pmm.?;

        const pml4_page = try pmm_mgr.create(paging.PageMem(.page4k));

        const pml4_vaddr = VAddr.fromInt(@intFromPtr(pml4_page));
        proc.addr_space_root = PAddr.fromVAddr(pml4_vaddr, null);
        arch.paging.copyKernelMappings(pml4_vaddr);

        proc.addr_space_id = arch.paging.allocAddrSpaceId() orelse return error.NoAddrSpaceId;
        errdefer if (!skip_cleanup) arch.paging.freeAddrSpaceId(proc.addr_space_id);

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
        errdefer if (!skip_cleanup) arch.paging.freeUserAddrSpace(proc.addr_space_root);

        const elf_result = try loadElf(proc, elf_binary, aslr_base);

        var view_page_mapped = false;
        const view_page = try pmm_mgr.create(paging.PageMem(.page4k));
        errdefer if (!skip_cleanup and !view_page_mapped) pmm_mgr.destroy(view_page);
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
        try arch.paging.mapPage(proc.addr_space_root, view_phys, view_vaddr, view_perms);
        // Once mapped, freeUserAddrSpace will reclaim view_page on error.
        view_page_mapped = true;
        try proc.vmm.insertKernelNode(view_vaddr, paging.PAGE4K, .{ .read = true }, .preserve);

        proc.perm_view_vaddr = view_vaddr;
        proc.perm_view_phys = view_phys;

        proc.initPermTable(initial_rights);

        if (initial_rights.restart) {
            proc.restart_context = try RestartContext.init(
                elf_result.entry,
                elf_result.data_vaddr,
                elf_result.data_content,
            );
        }
        errdefer if (!skip_cleanup) if (proc.restart_context) |*rc| rc.deinit();

        const initial_thread = try thread_mod.Thread.create(proc, elf_result.entry, proc.perm_view_vaddr.addr, DEFAULT_STACK_PAGES);

        // Insert initial thread handle at slot 1
        proc.insertThreadHandleAtSlot(1, initial_thread, thr_rights);

        if (parent) |p| {
            p._gen_lock.lock(@src());
            defer p._gen_lock.unlock();
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
            p.children[p.num_children] = slabRefNow(Process, proc);
            p.num_children += 1;
        }

        return proc;
    }

    pub fn createIdle() !*Process {
        const proc_alloc = try slab_instance.create();
        const proc = proc_alloc.ptr;
        // Same field-by-field pattern as `create`: a whole-struct
        // `.* = .{...}` would zero `_gen_lock`.
        proc.pid = @atomicRmw(u64, &pid_counter, .Add, 1, .monotonic);
        proc.parent = null;
        proc.alive = true;
        proc.restart_context = null;
        proc.addr_space_root = memory_init.kernel_addr_space_root;
        proc.addr_space_id = 0;
        proc.vmm = VirtualMemoryManager.init(
            VAddr.fromInt(address.AddrSpacePartition.user.start),
            VAddr.fromInt(address.AddrSpacePartition.user.end),
            memory_init.kernel_addr_space_root,
        );
        proc.threads = undefined;
        proc.num_threads = 0;
        proc.children = undefined;
        proc.num_children = 0;
        proc.perm_table = undefined;
        proc.perm_count = 0;
        proc.perm_lock = .{ .class = "Process.perm_lock" };
        proc.handle_counter = 1;
        proc.perm_view_vaddr = VAddr.fromInt(0);
        proc.perm_view_phys = PAddr.fromInt(0);
        proc.dma_mappings = undefined;
        proc.num_dma_mappings = 0;
        proc.msg_box = .{};
        proc.fault_box = .{};
        // Override class strings so lockdep treats `msg_box.lock` and
        // `fault_box.lock` as distinct classes. They never alias (one
        // serves IPC, the other fault delivery) and routinely appear
        // in opposite orderings against `Process._gen_lock`:
        //   * sysIpcReply: msg_box.lock → Process._gen_lock (ipc.zig:151)
        //   * faultBlock:  Process._gen_lock → fault_box.lock (process.zig:712)
        // Without per-instance class identity these would register as
        // an AB-BA cycle even though no single instance can be on both
        // sides of the cycle.
        proc.msg_box.lock.class = "MessageBox.msg_box.lock";
        proc.fault_box.lock.class = "MessageBox.fault_box.lock";
        proc.fault_reason = .none;
        proc.restart_count = 0;
        proc.perm_view_gen = 0;
        proc.cleanup_complete = false;
        proc.fault_handler_proc = null;
        proc.faulted_thread_slots = 0;
        proc.suspended_thread_slots = 0;
        proc.thread_handle_rights = ThreadHandleRights.full;
        proc.max_thread_priority = .normal;
        proc.fault_handler_targets_head = null;
        proc.fault_handler_targets_next = null;
        proc.had_self_fault_handler = true;
        proc.vm = null;
        proc.initPermTable(.{});
        return proc;
    }
};

/// Remove `target` from `box` if it appears as the pending sender or in
/// the wait queue. Used during thread teardown to avoid leaving dangling
/// pointers in fault boxes.
fn scrubFromFaultBox(box: *MessageBox, target: *Thread) void {
    box.lock.lock(@src());
    defer box.lock.unlock();
    if (box.isPendingReply() and
        box.pending_thread != null and
        box.pending_thread.?.ptr == target)
    {
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
    const entropy = arch.time.readTimestamp(true);
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
    kprof.enter(.proc_load_elf);
    defer kprof.exit(.proc_load_elf);
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

    const pmm_mgr = &pmm.global_pmm.?;
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
    while (i < phdr_count) {
        const off = phdr_offset + i * phdr_size;
        const phdr = std.mem.bytesAsValue(elf.Elf64_Phdr, elf_binary[off..][0..@sizeOf(elf.Elf64_Phdr)]);
        if (phdr.p_type != elf.PT_LOAD) {
            i += 1;
            continue;
        }

        // Use checked arithmetic for all segment address computations
        // to prevent overflow into kernel address space.
        const seg_start = std.math.add(u64, aslr_base, phdr.p_vaddr) catch return error.InvalidElf;
        const seg_file_end = std.math.add(u64, seg_start, phdr.p_filesz) catch return error.InvalidElf;
        const seg_mem_end = std.math.add(u64, seg_start, phdr.p_memsz) catch return error.InvalidElf;

        // All segment addresses must remain in user address space.
        if (!address.AddrSpacePartition.user.contains(seg_start)) return error.InvalidElf;
        if (seg_file_end > 0 and !address.AddrSpacePartition.user.contains(seg_file_end -| 1)) return error.InvalidElf;
        if (seg_mem_end > 0 and !address.AddrSpacePartition.user.contains(seg_mem_end -| 1)) return error.InvalidElf;

        // Track segments. Adjacent PT_LOAD segments sharing a boundary page
        // is normal on aarch64 (ELF p_align=64KB, kernel page=4KB) and on
        // ReleaseSafe x64 (.text and .rodata adjacent within a page).
        if (num_load_segments >= MAX_LOAD_SEGMENTS) return error.InvalidElf;
        const page_aligned_start = std.mem.alignBackward(u64, seg_start, paging.PAGE4K);
        const page_aligned_end = std.mem.alignForward(u64, seg_mem_end, paging.PAGE4K);
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
        i += 1;
    }

    if (lowest_va >= highest_va and !has_bss) return error.InvalidElf;

    const page_start = std.mem.alignBackward(u64, lowest_va, paging.PAGE4K);
    const page_end = std.mem.alignForward(u64, highest_va, paging.PAGE4K);

    // Enforce a maximum on total mapped size to prevent memory exhaustion.
    const total_mapped = (page_end - page_start) + (if (has_bss and bss_end > bss_start) bss_end - bss_start else 0);
    if (total_mapped > MAX_ELF_MAPPED_SIZE) return error.InvalidElf;

    if (page_end <= page_start) return error.InvalidElf;

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
    while (page_va < page_end) {
        const page = try pmm_mgr.create(paging.PageMem(.page4k));
        const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
        try arch.paging.mapPage(proc.addr_space_root, phys, VAddr.fromInt(page_va), load_perms);
        page_va += paging.PAGE4K;
    }

    i = 0;
    while (i < phdr_count) {
        const off = phdr_offset + i * phdr_size;
        const phdr = std.mem.bytesAsValue(elf.Elf64_Phdr, elf_binary[off..][0..@sizeOf(elf.Elf64_Phdr)]);
        if (phdr.p_type != elf.PT_LOAD) {
            i += 1;
            continue;
        }
        if (phdr.p_filesz == 0) {
            i += 1;
            continue;
        }

        const seg_vaddr = aslr_base + phdr.p_vaddr;
        if (phdr.p_offset + phdr.p_filesz > elf_binary.len) return error.InvalidElf;

        writeToUserPages(proc.addr_space_root, seg_vaddr, elf_binary[phdr.p_offset..][0..phdr.p_filesz]);
        i += 1;
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

    // Synchronize the instruction cache after writing the ELF text via the
    // physmap (D-cache) view. On x86 this is a no-op because the I-cache
    // snoops D-cache writes. On aarch64 the I/D caches are split and the
    // first instruction fetch from a freshly loaded page returns stale
    // bytes (typically zero) until the I-cache is invalidated and the
    // D-cache lines containing the new code are cleaned to the point of
    // unification. Without this, every newly created process raises an
    // instruction-abort exception at its entry point on a real CPU
    // (TCG masks the bug by re-translating from memory each time).
    arch.cpu.syncInstructionCache();

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
        const paddr = arch.paging.resolveVaddr(addr_space_root, VAddr.fromInt(page_base)) orelse return;
        const physmap_addr = VAddr.fromPAddr(paddr, null).addr + page_offset;
        const chunk_len = @min(data.len - offset, paging.PAGE4K - page_offset);
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        @memcpy(dst[0..chunk_len], data[offset..][0..chunk_len]);
        // Clean the just-written physmap range to the Point of Unification
        // so that a later `ic ivau`/`ic ialluis` makes the new code visible
        // to instruction fetch on aarch64. No-op on x86-64.
        arch.cpu.cleanDcacheToPou(physmap_addr, chunk_len);
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
    while (s < shdr_count) {
        const off = shdr_offset + s * shdr_size;
        const shdr = std.mem.bytesAsValue(elf.Elf64_Shdr, elf_binary[off..][0..@sizeOf(elf.Elf64_Shdr)]);
        if (shdr.sh_type == elf.SHT_RELA) {
            return .{ .offset = shdr.sh_offset, .size = shdr.sh_size };
        }
        s += 1;
    }
    return null;
}

fn applyRelocations(proc: *Process, aslr_base: u64, elf_binary: []const u8, rela_offset: u64, rela_size: u64) !void {
    kprof.enter(.proc_apply_relocations);
    defer kprof.exit(.proc_apply_relocations);
    const entry_size = @sizeOf(elf.Elf64_Rela);
    const num_entries = rela_size / entry_size;

    // Validate the entire rela table fits within the ELF binary.
    const rela_total = std.math.mul(u64, num_entries, entry_size) catch return error.InvalidElf;
    const rela_end = std.math.add(u64, rela_offset, rela_total) catch return error.InvalidElf;
    if (rela_end > elf_binary.len) return error.InvalidElf;

    var r: u64 = 0;
    while (r < num_entries) {
        const off = rela_offset + r * entry_size;
        const rela = std.mem.bytesAsValue(elf.Elf64_Rela, elf_binary[off..][0..entry_size]);

        const rela_type = @as(u32, @truncate(rela.r_info));
        if (!arch.paging.isRelativeRelocation(rela_type)) {
            r += 1;
            continue;
        }

        // Validate relocation target stays in user address space.
        const target_vaddr = std.math.add(u64, aslr_base, rela.r_offset) catch return error.InvalidElf;
        const target_end = std.math.add(u64, target_vaddr, 8) catch return error.InvalidElf;
        if (!address.AddrSpacePartition.user.contains(target_vaddr)) return error.InvalidElf;
        if (!address.AddrSpacePartition.user.contains(target_end - 1)) return error.InvalidElf;

        // The 8-byte write is addressed through the physmap of a single
        // resolved page. If target_vaddr straddles a page boundary, bytes
        // past the first page would land in the PHYSICALLY-adjacent frame
        // (whatever the PMM placed next to this one) — an arbitrary kernel
        // write primitive. Require the write to stay within one page.
        const page_base = std.mem.alignBackward(u64, target_vaddr, paging.PAGE4K);
        if (target_end - page_base > paging.PAGE4K) return error.InvalidElf;

        const value: u64 = @bitCast(@as(i64, rela.r_addend) +% @as(i64, @bitCast(aslr_base)));

        const paddr = arch.paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(page_base)) orelse return error.InvalidElf;
        const physmap_addr = VAddr.fromPAddr(paddr, null).addr + (target_vaddr - page_base);
        const ptr: *u64 = @ptrFromInt(physmap_addr);
        ptr.* = value;
        r += 1;
    }
}

pub var slab_instance: ProcessAllocator = undefined;
var pid_counter: u64 = 1;

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

const CrashReason = zag.perms.permissions.CrashReason;
const DeadProcessInfo = zag.perms.permissions.DeadProcessInfo;
const DeviceRegion = zag.memory.device_region.DeviceRegion;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const ProcessRights = zag.perms.permissions.ProcessRights;
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
    msg_waiters_head: ?*Thread = null,
    msg_waiters_tail: ?*Thread = null,
    receiver: ?*Thread = null,
    pending_caller: ?*Thread = null,
    pending_reply: bool = false,
    crash_reason: CrashReason,
    restart_count: u16,
    perm_view_gen: u64 = 0,
    handle_refcount: u32 = 0,
    cleanup_complete: bool = false,

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

    fn syncUserView(self: *Process) void {
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

    /// Look up two handles atomically under a single perm_lock acquisition.
    /// Returns both entries or null if either handle is missing.
    pub fn getPermByHandlePair(self: *Process, h1: u64, h2: u64) ?struct { first: PermissionEntry, second: PermissionEntry } {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
        var e1: ?PermissionEntry = null;
        var e2: ?PermissionEntry = null;
        for (self.perm_table) |entry| {
            if (entry.object == .empty) continue;
            if (entry.handle == h1) e1 = entry;
            if (entry.handle == h2) e2 = entry;
        }
        if (e1 != null and e2 != null) return .{ .first = e1.?, .second = e2.? };
        return null;
    }

    /// Look up a shared_memory handle and atomically increment its refcount
    /// while still holding perm_lock.  This prevents a concurrent revoke_perm
    /// from freeing the SharedMemory between lookup and use.
    pub fn acquireShmByHandle(self: *Process, handle_id: u64) ?struct { shm: *SharedMemory, rights: u16 } {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
        for (self.perm_table) |entry| {
            if (entry.object != .empty and entry.handle == handle_id) {
                if (entry.object != .shared_memory) return null;
                const shm = entry.object.shared_memory;
                shm.incRef();
                return .{ .shm = shm, .rights = entry.rights };
            }
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
        self.crash_reason = reason;
        const should_restart = self.restart_context != null;
        if (!should_restart) {
            self.alive = false;
        }

        // Collect blocked threads before marking all as exited.
        var blocked: [MAX_THREADS]*Thread = undefined;
        var num_blocked: u32 = 0;
        for (self.threads[0..self.num_threads]) |thread| {
            if (thread.state == .blocked) {
                blocked[num_blocked] = thread;
                num_blocked += 1;
            }
            thread.state = .exited;
        }
        self.lock.unlock();

        // Remove blocked threads from external wait structures and deinit them.
        // Each deinit calls removeThread which decrements num_threads.
        // The last thread's deinit triggers lastThreadExited.
        for (blocked[0..num_blocked]) |thread| {
            if (thread.futex_paddr.addr != 0) {
                futex.removeBlockedThread(thread);
            }
            if (thread.ipc_server) |server| {
                server.lock.lock();
                if (server.pending_caller == thread) {
                    server.pending_caller = null;
                    server.pending_reply = false;
                } else {
                    var prev: ?*Thread = null;
                    var cur = server.msg_waiters_head;
                    while (cur) |t| {
                        if (t == thread) {
                            if (prev) |p| {
                                p.next = t.next;
                            } else {
                                server.msg_waiters_head = t.next;
                            }
                            if (server.msg_waiters_tail == t) {
                                server.msg_waiters_tail = prev;
                            }
                            t.next = null;
                            break;
                        }
                        prev = t;
                        cur = t.next;
                    }
                }
                thread.ipc_server = null;
                server.lock.unlock();
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
        if (self.crash_reason == .none) {
            self.crash_reason = .normal_exit;
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

        // Convert parent's entry to dead_process even if we have children (zombie).
        if (self.parent) |p| {
            p.convertToDeadProcess(self);
        }

        if (self.num_children == 0) {
            self.cleanupPhase2();
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
        // head so the restarted process can recv it again.
        self.lock.lock();
        if (self.pending_caller) |pc| {
            pc.next = self.msg_waiters_head;
            self.msg_waiters_head = pc;
            if (self.msg_waiters_tail == null) {
                self.msg_waiters_tail = pc;
            }
            self.pending_caller = null;
        }
        self.pending_reply = false;
        self.receiver = null; // old thread is dead
        self.lock.unlock();

        self.vmm.resetForRestart();

        self.perm_lock.lock();
        for (&self.perm_table) |*entry| {
            if (entry.object == .vm_reservation) {
                entry.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
            }
        }
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
                    const field0_pa = PAddr.fromInt(parent.perm_view_phys.addr + idx * @sizeOf(UserViewEntry) + 16);
                    _ = futex.wake(field0_pa, 1);
                }
                return;
            }
        }
    }

    fn cleanupIpcState(self: *Process) void {
        self.lock.lock();

        // Unblock all message waiters with E_NOENT
        var waiter = self.msg_waiters_head;
        while (waiter) |w| {
            const next_w = w.next;
            w.ipc_server = null;
            w.next = null;
            w.ctx.regs.rax = @bitCast(@as(i64, -10));
            while (w.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            w.state = .ready;
            const target_core = if (w.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
            sched.enqueueOnCore(target_core, w);
            waiter = next_w;
        }

        // Unblock pending caller if any
        if (self.pending_caller) |pc| {
            pc.ipc_server = null;
            pc.ctx.regs.rax = @bitCast(@as(i64, -10));
            while (pc.on_cpu.load(.acquire)) std.atomic.spinLoopHint();
            pc.state = .ready;
            const target_core = if (pc.core_affinity) |mask| @as(u64, @ctz(mask)) else arch.coreID();
            sched.enqueueOnCore(target_core, pc);
        }

        self.msg_waiters_head = null;
        self.msg_waiters_tail = null;
        self.receiver = null;
        self.pending_caller = null;
        self.pending_reply = false;
        self.lock.unlock();

        // Clean up threads that are blocked waiting for reply from other processes
        for (self.threads[0..self.num_threads]) |thread| {
            if (thread.ipc_server) |server| {
                server.lock.lock();
                if (server.pending_caller == thread) {
                    server.pending_caller = null;
                    server.pending_reply = false;
                } else {
                    // Remove from server's wait queue
                    var prev: ?*Thread = null;
                    var cur = server.msg_waiters_head;
                    while (cur) |t| {
                        if (t == thread) {
                            if (prev) |p| {
                                p.next = t.next;
                            } else {
                                server.msg_waiters_head = t.next;
                            }
                            if (server.msg_waiters_tail == t) {
                                server.msg_waiters_tail = prev;
                            }
                            t.next = null;
                            break;
                        }
                        prev = t;
                        cur = t.next;
                    }
                }
                thread.ipc_server = null;
                server.lock.unlock();
            }
        }
    }

    fn cleanupPhase1(self: *Process) void {
        self.cleanupIpcState();
        self.cleanupDmaMappings();
        self.vmm.deinit();

        for (&self.perm_table) |*entry| {
            switch (entry.object) {
                .shared_memory => |shm| shm.decRef(),
                .device_region => |device| {
                    returnDeviceHandleUpTree(self, entry.rights, device);
                },
                .core_pin => |cp| {
                    sched.unpinByRevoke(cp.core_id, cp.thread_tid);
                },
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

    pub fn convertToDeadProcess(parent: *Process, child: *Process) void {
        parent.perm_lock.lock();
        defer parent.perm_lock.unlock();
        for (parent.perm_table[1..], 1..) |*slot, idx| {
            const matches = switch (slot.object) {
                .process => |p| @intFromPtr(p) == @intFromPtr(child),
                else => false,
            };
            if (matches) {
                // Refcount stays the same — still one reference, just different type
                slot.object = .{ .dead_process = child };
                parent.syncUserView();
                if (parent.perm_view_phys.addr != 0) {
                    const field0_pa = PAddr.fromInt(parent.perm_view_phys.addr + idx * @sizeOf(UserViewEntry) + 16);
                    _ = futex.wake(field0_pa, 1);
                }
                return;
            }
        }
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

    pub fn create(elf_binary: []const u8, initial_rights: ProcessRights, parent: ?*Process) !*Process {
        const proc = try allocator.create(Process);
        errdefer allocator.destroy(proc);

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
            .crash_reason = .none,
            .restart_count = 0,
        };

        const pmm_iface = pmm.global_pmm.?.allocator();

        const pml4_page = try pmm_iface.create(paging.PageMem(.page4k));
        errdefer pmm_iface.destroy(pml4_page);
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

        const elf_result = try loadElf(proc, elf_binary, aslr_base);

        const view_page = try pmm_iface.create(paging.PageMem(.page4k));
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
            errdefer restart_context_mod.destroy(proc.restart_context.?);
        }

        _ = try thread_mod.Thread.create(proc, elf_result.entry, proc.perm_view_vaddr.addr, DEFAULT_STACK_PAGES);

        if (parent) |p| {
            p.lock.lock();
            defer p.lock.unlock();
            if (p.num_children >= MAX_CHILDREN) {
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
            .crash_reason = .none,
            .restart_count = 0,
        };
        proc.initPermTable(.{});
        return proc;
    }
};

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

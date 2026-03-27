const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const elf = std.elf;
const futex = zag.sched.futex;
const iommu = zag.arch.x64.iommu;
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
const VAddrRange = zag.sched.restart_context.VAddrRange;
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
    crash_reason: CrashReason,
    restart_count: u16,

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
        for (&self.perm_table, 0..) |*entry, i| {
            view_ptr[i] = UserViewEntry.fromKernelEntry(entry.*);
        }
    }

    pub fn getPermByHandle(self: *Process, handle_id: u64) ?PermissionEntry {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
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
                self.syncUserView();
                return handle_id;
            }
        }
        return error.PermTableFull;
    }

    pub fn removePerm(self: *Process, handle_id: u64) !void {
        if (handle_id == HANDLE_SELF) return error.CannotRevokeSelf;
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
        for (self.perm_table[1..]) |*slot| {
            if (slot.object != .empty and slot.handle == handle_id) {
                slot.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
                self.syncUserView();
                return;
            }
        }
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
        if (self.restart_context == null) {
            self.alive = false;
        }
        for (self.threads[0..self.num_threads]) |thread| {
            thread.state = .exited;
        }
        self.lock.unlock();
        if (self.num_threads == 0) {
            self.exit();
        }
    }

    pub fn killSubtree(self: *Process) void {
        var i: u64 = 0;
        while (i < self.num_children) : (i += 1) {
            self.children[i].killSubtree();
        }
        self.kill(.none);
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

    pub fn exit(self: *Process) void {
        self.lock.lock();
        if (!self.alive) {
            self.lock.unlock();
            return;
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

        self.cleanupPhase1();

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

    fn cleanupPhase1(self: *Process) void {
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
                .vm_reservation, .process, .dead_process, .empty => {},
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
        allocator.destroy(self);
    }

    fn convertToDeadProcess(parent: *Process, child: *Process) void {
        parent.perm_lock.lock();
        defer parent.perm_lock.unlock();
        for (parent.perm_table[1..], 1..) |*slot, idx| {
            const matches = switch (slot.object) {
                .process => |p| @intFromPtr(p) == @intFromPtr(child),
                else => false,
            };
            if (matches) {
                slot.object = .{ .dead_process = .{
                    .crash_reason = child.crash_reason,
                    .restart_count = child.restart_count,
                } };
                parent.syncUserView();
                if (parent.perm_view_phys.addr != 0) {
                    const field0_pa = PAddr.fromInt(parent.perm_view_phys.addr + idx * @sizeOf(UserViewEntry) + 16);
                    _ = futex.wake(field0_pa, 1);
                }
                return;
            }
        }
    }

    pub fn clearPermByObject(self: *Process, target: anytype) void {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();
        var changed = false;
        for (self.perm_table[1..]) |*slot| {
            const matches = switch (slot.object) {
                .process => |p| @intFromPtr(p) == @intFromPtr(target),
                else => false,
            };
            if (matches) {
                slot.* = .{ .handle = std.math.maxInt(u64), .object = .empty, .rights = 0 };
                self.perm_count -= 1;
                changed = true;
            }
        }
        if (changed) self.syncUserView();
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
                iommu.unmapDmaPages(m.device, m.dma_base, m.num_pages);
                m.active = false;
            }
        }
        self.num_dma_mappings = 0;
    }

    pub fn returnDeviceHandleUpTree(source: *Process, rights: u16, device: *DeviceRegion) void {
        var ancestor = source.parent;
        while (ancestor) |anc| {
            if (anc.alive) {
                _ = anc.insertPerm(.{
                    .handle = 0,
                    .object = .{ .device_region = device },
                    .rights = rights,
                }) catch {};
                return;
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
                elf_result.code_range,
                elf_result.rodata_range,
                elf_result.data_vaddr,
                elf_result.data_content,
                .{ .vaddr = view_vaddr, .size = paging.PAGE4K },
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
    code_range: VAddrRange,
    rodata_range: VAddrRange,
    data_vaddr: VAddr,
    data_content: []const u8,
};

fn loadElf(proc: *Process, elf_binary: []const u8, aslr_base: u64) !ElfLoadResult {
    if (elf_binary.len < @sizeOf(elf.Elf64_Ehdr)) return error.InvalidElf;

    const ehdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, elf_binary[0..@sizeOf(elf.Elf64_Ehdr)]);
    if (!std.mem.eql(u8, ehdr.e_ident[0..4], "\x7fELF")) return error.InvalidElf;
    if (ehdr.e_ident[elf.EI_CLASS] != elf.ELFCLASS64) return error.InvalidElf;

    const phdr_offset = ehdr.e_phoff;
    const phdr_size = @as(u64, ehdr.e_phentsize);
    const phdr_count = @as(u64, ehdr.e_phnum);

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

    var code_range = VAddrRange{ .vaddr = VAddr.fromInt(0), .size = 0 };
    var rodata_range = VAddrRange{ .vaddr = VAddr.fromInt(0), .size = 0 };
    var data_vaddr = VAddr.fromInt(0);
    var data_offset: u64 = 0;
    var data_filesz: u64 = 0;

    var i: u64 = 0;
    while (i < phdr_count) : (i += 1) {
        const off = phdr_offset + i * phdr_size;
        const phdr = std.mem.bytesAsValue(elf.Elf64_Phdr, elf_binary[off..][0..@sizeOf(elf.Elf64_Phdr)]);
        if (phdr.p_type != elf.PT_LOAD) continue;

        const seg_start = aslr_base + phdr.p_vaddr;
        const seg_file_end = seg_start + phdr.p_filesz;
        const seg_mem_end = seg_start + phdr.p_memsz;

        const writable = (phdr.p_flags & elf.PF_W) != 0;
        const executable = (phdr.p_flags & elf.PF_X) != 0;

        if (!writable and executable) {
            code_range = .{ .vaddr = VAddr.fromInt(seg_start), .size = phdr.p_memsz };
        } else if (!writable and !executable) {
            rodata_range = .{ .vaddr = VAddr.fromInt(seg_start), .size = phdr.p_memsz };
        } else if (writable and !executable) {
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

    return .{
        .entry = VAddr.fromInt(aslr_base + ehdr.e_entry),
        .code_range = code_range,
        .rodata_range = rodata_range,
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
    if (shdr_offset + shdr_size * shdr_count > elf_binary.len) return null;

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

    var r: u64 = 0;
    while (r < num_entries) : (r += 1) {
        const off = rela_offset + r * entry_size;
        if (off + entry_size > elf_binary.len) return error.InvalidElf;
        const rela = std.mem.bytesAsValue(elf.Elf64_Rela, elf_binary[off..][0..entry_size]);

        const rela_type = @as(u32, @truncate(rela.r_info));
        if (rela_type != @intFromEnum(elf.R_X86_64.RELATIVE)) continue;

        const target_vaddr = aslr_base + rela.r_offset;
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

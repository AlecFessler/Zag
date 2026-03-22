const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const device_region_mod = zag.memory.device_region;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const restart_context_mod = zag.sched.restart_context;
const thread_mod = zag.sched.thread;

const KernelObject = zag.perms.permissions.KernelObject;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const ProcessRights = zag.perms.permissions.ProcessRights;
const RestartContext = zag.sched.restart_context.RestartContext;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const SpinLock = zag.sched.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;

pub const USER_CODE_BASE: u64 = 0x400000;
pub const DEFAULT_STACK_PAGES: u32 = 4;
pub const MAX_PERMS: usize = 64;
pub const HANDLE_SELF: u64 = 0;

pub const ProcessAllocator = SlabAllocator(Process, false, 0, 64);

pub const Process = struct {
    pid: u64,
    parent: ?*Process,
    alive: bool,
    restart_context: ?*RestartContext,
    addr_space_root: PAddr,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]*Thread,
    num_threads: u64,
    lock: SpinLock,
    perm_table: [MAX_PERMS]PermissionEntry,
    perm_count: u32,
    perm_lock: SpinLock,
    handle_counter: u64,

    pub const MAX_THREADS = 16;

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
                return;
            }
        }
        return error.NotFound;
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

    pub fn kill(self: *Process) void {
        self.lock.lock();
        defer self.lock.unlock();
        if (!self.alive) return;
        self.alive = false;
        for (self.threads[0..self.num_threads], 0..) |thread, i| {
            thread.state = .exited;
            thread.last_in_proc = (i == self.num_threads - 1);
        }
        if (self.num_threads == 0) {
            self.deinitUnlocked();
        }
    }

    pub fn disableRestart(self: *Process) void {
        if (self.restart_context) |rc| {
            restart_context_mod.destroy(rc);
            self.restart_context = null;
        }
    }

    pub fn deinit(self: *Process) void {
        self.lock.lock();
        self.deinitUnlocked();
    }

    fn deinitUnlocked(self: *Process) void {
        self.lock.unlock();

        for (&self.perm_table) |*entry| {
            switch (entry.object) {
                .shared_memory => |shm| shm.decRef(),
                .device_region => |dr| device_region_mod.destroy(dr),
                .vm_reservation, .process, .empty => {},
            }
        }

        if (self.restart_context) |rc| restart_context_mod.destroy(rc);

        arch.freeUserAddrSpace(self.addr_space_root);

        const pmm_iface = pmm.global_pmm.?.allocator();
        const pml4: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(self.addr_space_root, null).addr);
        pmm_iface.destroy(pml4);

        allocator.destroy(self);
    }

    pub fn create(elf_binary: []const u8, initial_rights: ProcessRights, parent: ?*Process) !*Process {
        if (elf_binary.len > paging.PAGE4K) return error.BinaryTooLarge;

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
            .lock = .{},
            .perm_table = undefined,
            .perm_count = 0,
            .perm_lock = .{},
            .handle_counter = 1,
        };

        proc.initPermTable(initial_rights);

        const pmm_iface = pmm.global_pmm.?.allocator();

        const pml4_page = try pmm_iface.create(paging.PageMem(.page4k));
        errdefer pmm_iface.destroy(pml4_page);
        @memset(std.mem.asBytes(pml4_page), 0);

        const pml4_vaddr = VAddr.fromInt(@intFromPtr(pml4_page));
        proc.addr_space_root = PAddr.fromVAddr(pml4_vaddr, null);
        arch.copyKernelMappings(pml4_vaddr);

        proc.vmm = VirtualMemoryManager.init(
            VAddr.fromInt(address.AddrSpacePartition.user.start),
            VAddr.fromInt(address.AddrSpacePartition.user.end),
            proc.addr_space_root,
        );

        const code_page = try pmm_iface.create(paging.PageMem(.page4k));
        errdefer pmm_iface.destroy(code_page);
        @memset(std.mem.asBytes(code_page), 0);
        @memcpy(std.mem.asBytes(code_page)[0..elf_binary.len], elf_binary);

        const code_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(code_page)), null);
        const code_perms = MemoryPerms{
            .write_perm = .no_write,
            .execute_perm = .execute,
            .cache_perm = .write_back,
            .global_perm = .not_global,
            .privilege_perm = .user,
        };
        try arch.mapPage(proc.addr_space_root, code_phys, VAddr.fromInt(USER_CODE_BASE), code_perms);

        proc.restart_context = try restart_context_mod.create(elf_binary, VAddr.fromInt(USER_CODE_BASE));
        errdefer restart_context_mod.destroy(proc.restart_context.?);

        _ = try thread_mod.Thread.create(proc, VAddr.fromInt(USER_CODE_BASE), 0, DEFAULT_STACK_PAGES);

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
            .lock = .{},
            .perm_table = undefined,
            .perm_count = 0,
            .perm_lock = .{},
            .handle_counter = 1,
        };
        proc.initPermTable(.{});
        return proc;
    }
};

pub var allocator: std.mem.Allocator = undefined;
var pid_counter: u64 = 1;

const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const KernelObject = zag.perms.permissions.KernelObject;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PermissionEntry = zag.perms.permissions.PermissionEntry;
const ProcessRights = zag.perms.permissions.ProcessRights;
const PrivilegePerm = zag.perms.privilege.PrivilegePerm;
const SlabAllocator = zag.memory.slab_allocator.SlabAllocator;
const SpinLock = zag.sched.sync.SpinLock;
const Thread = zag.sched.thread.Thread;
const VAddr = zag.memory.address.VAddr;
const VirtualMemoryManager = zag.memory.vmm.VirtualMemoryManager;

pub const USER_CODE_BASE: u64 = 0x400000;
pub const MAX_PERMS = 64;
pub const SLOT_SELF = 0;

pub const ProcessAllocator = SlabAllocator(
    Process,
    false,
    0,
    64,
);

pub const Process = struct {
    pid: u64,
    privilege: PrivilegePerm,
    addr_space_root: VAddr,
    vmm: VirtualMemoryManager,
    threads: [MAX_THREADS]*Thread,
    num_threads: u64,
    lock: SpinLock = .{},
    perm_table: [MAX_PERMS]PermissionEntry,
    perm_count: u32,
    perm_lock: SpinLock = .{},

    pub const MAX_THREADS = 16;

    pub fn initPermTable(self: *Process, self_rights: ProcessRights) void {
        for (&self.perm_table) |*entry| {
            entry.* = .{ .object = .empty, .rights = 0 };
        }
        self.perm_table[SLOT_SELF] = .{
            .object = .{ .process = self },
            .rights = @bitCast(self_rights),
        };
        self.perm_count = 1;
    }

    pub fn insertPerm(self: *Process, entry: PermissionEntry) !u32 {
        self.perm_lock.lock();
        defer self.perm_lock.unlock();

        for (self.perm_table[1..], 1..) |*slot, idx| {
            if (slot.object == .empty) {
                slot.* = entry;
                self.perm_count += 1;
                return @intCast(idx);
            }
        }
        return error.PermTableFull;
    }

    pub fn removePerm(self: *Process, index: u32) !void {
        if (index == SLOT_SELF) return error.CannotRevokeSelf;
        if (index >= MAX_PERMS) return error.InvalidIndex;

        self.perm_lock.lock();
        defer self.perm_lock.unlock();

        if (self.perm_table[index].object == .empty) return error.InvalidIndex;
        self.perm_table[index] = .{ .object = .empty, .rights = 0 };
        self.perm_count -= 1;
    }

    pub fn getPerm(self: *Process, index: u32) ?PermissionEntry {
        if (index >= MAX_PERMS) return null;

        self.perm_lock.lock();
        defer self.perm_lock.unlock();

        const entry = self.perm_table[index];
        if (entry.object == .empty) return null;
        return entry;
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

    pub fn deinit(self: *Process) void {
        for (&self.perm_table) |*entry| {
            switch (entry.object) {
                .shared_memory => |shm| shm.decRef(),
                .vm_reservation => {
                    // TODO: decommit pages, free physical memory, release VA range
                },
                .process => {},
                .empty => {},
            }
        }

        const pmm_iface = pmm.global_pmm.?.allocator();
        arch.freeUserAddrSpace(self.addr_space_root, pmm_iface);
        allocator.destroy(self);
    }

    pub fn createUserProcess(
        binary: []const u8,
    ) !*Process {
        if (binary.len > paging.PAGE4K) return error.BinaryTooLarge;

        const proc = try allocator.create(Process);
        errdefer allocator.destroy(proc);

        proc.pid = @atomicRmw(u64, &pid_counter, .Add, 1, .monotonic);
        proc.privilege = .user;
        proc.lock = .{};
        proc.perm_lock = .{};
        proc.num_threads = 0;

        proc.initPermTable(.{
            .destroy = true,
            .spawn_thread = true,
            .spawn_process = true,
            .mem_reserve = true,
            .set_affinity = true,
        });

        const pmm_iface = pmm.global_pmm.?.allocator();

        const new_addr_space_root_page = try pmm_iface.create(paging.PageMem(.page4k));
        errdefer pmm_iface.destroy(new_addr_space_root_page);
        const new_addr_space_root_bytes: [*]u8 = @ptrCast(new_addr_space_root_page);
        @memset(new_addr_space_root_bytes[0..paging.PAGE4K], 0);

        proc.addr_space_root = VAddr.fromInt(@intFromPtr(new_addr_space_root_page));
        arch.copyKernelMappings(proc.addr_space_root);

        proc.vmm = VirtualMemoryManager.init(
            VAddr.fromInt(address.AddrSpacePartition.user.start),
            VAddr.fromInt(address.AddrSpacePartition.user.end),
        );

        const code_phys_page = try pmm_iface.create(paging.PageMem(.page4k));
        errdefer pmm_iface.destroy(code_phys_page);
        const code_bytes: [*]u8 = @ptrCast(code_phys_page);
        @memset(code_bytes[0..paging.PAGE4K], 0);
        @memcpy(code_bytes[0..binary.len], binary);

        const code_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(code_phys_page)), null);
        try arch.mapPage(
            proc.addr_space_root,
            code_phys,
            VAddr.fromInt(USER_CODE_BASE),
            .page4k,
            .{ .execute_perm = .execute, .privilege_perm = .user },
            pmm_iface,
        );

        const entry: *const fn () void = @ptrFromInt(USER_CODE_BASE);
        _ = try Thread.createThread(proc, entry, null);

        return proc;
    }
};

pub var allocator: std.mem.Allocator = undefined;

pub var global_kproc: Process = .{
    .pid = 0,
    .privilege = .kernel,
    .addr_space_root = undefined,
    .vmm = undefined,
    .threads = undefined,
    .num_threads = 0,
    .lock = .{},
    .perm_table = undefined,
    .perm_count = 0,
    .perm_lock = .{},
};

var pid_counter: u64 = 1;

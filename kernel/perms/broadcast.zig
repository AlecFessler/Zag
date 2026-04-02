const std = @import("std");
const zag = @import("zag");

const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const PAddr = zag.memory.address.PAddr;
const Process = zag.sched.process.Process;
const SpinLock = zag.sched.sync.SpinLock;
const VAddr = zag.memory.address.VAddr;

pub const BROADCAST_TABLE_CAPACITY: usize = 256;
pub const BROADCAST_OFFSET: u64 = 0x8000_0000_0000_0000;

pub const BroadcastEntry = extern struct {
    handle: u64,
    payload: u64,
};

fn getEntries() *[BROADCAST_TABLE_CAPACITY]BroadcastEntry {
    return @ptrFromInt(VAddr.fromPAddr(phys_page, null).addr);
}
var internal_procs: [BROADCAST_TABLE_CAPACITY]?*Process = .{null} ** BROADCAST_TABLE_CAPACITY;
var count: u32 = 0;
var lock: SpinLock = .{};
var phys_page: PAddr = PAddr.fromInt(0);

pub fn init() void {
    const pmm_iface = pmm.global_pmm.?.allocator();
    const page = pmm_iface.create(paging.PageMem(.page4k)) catch @panic("broadcast table: out of memory");
    @memset(std.mem.asBytes(page), 0);
    phys_page = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
}

pub fn physPage() PAddr {
    return phys_page;
}

pub fn insert(proc: *Process, payload: u64) error{ TableFull, DuplicatePayload }!void {
    lock.lock();
    defer lock.unlock();

    // A killed process's threads may still be mid-syscall on another core
    // (kill sets .exited but threads finish their current syscall before the
    // scheduler preempts them). Reject inserts from dead processes so a
    // racing broadcast syscall doesn't re-populate the table after
    // removeByProcess already ran in cleanupPhase1.
    if (!proc.alive) return error.TableFull;
    if (count >= BROADCAST_TABLE_CAPACITY) return error.TableFull;

    const entries = getEntries();
    for (entries[0..count]) |*entry| {
        if (entry.payload == payload) return error.DuplicatePayload;
    }

    const slot: usize = count;
    const handle = BROADCAST_OFFSET + @as(u64, slot);
    entries[slot] = .{ .handle = handle, .payload = payload };
    internal_procs[slot] = proc;
    count += 1;
}

pub fn removeByProcess(proc: *Process) void {
    lock.lock();
    defer lock.unlock();

    const e = getEntries();
    var i: usize = 0;
    while (i < count) {
        if (internal_procs[i] == proc) {
            count -= 1;
            if (i < count) {
                e[i] = e[count];
                internal_procs[i] = internal_procs[count];
                e[i].handle = BROADCAST_OFFSET + @as(u64, i);
            }
            e[count] = .{ .handle = 0, .payload = 0 };
            internal_procs[count] = null;
        } else {
            i += 1;
        }
    }
}

pub fn resolveHandle(handle: u64) ?*Process {
    if (handle < BROADCAST_OFFSET) return null;
    lock.lock();
    defer lock.unlock();
    const index = handle - BROADCAST_OFFSET;
    if (index >= count) return null;
    if (getEntries()[index].handle != handle) return null;
    return internal_procs[index];
}


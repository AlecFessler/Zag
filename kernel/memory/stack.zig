const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;

const address = zag.memory.address;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;
const SpinLock = zag.sched.sync.SpinLock;

const STACK_RANGE_START: u64 = address.KernelVA.kernel_stacks.start;
const STACK_RANGE_END: u64 = address.KernelVA.kernel_stacks.end;
const SLOT_SIZE: u64 = address.KERNEL_STACK_SLOT_SIZE;
const STACK_PAGES: u64 = address.KERNEL_STACK_PAGES;
const MAX_SLOTS: u64 = (STACK_RANGE_END - STACK_RANGE_START) / SLOT_SIZE;

const FREELIST_CAP: usize = 512;

var next_slot = std.atomic.Value(u64).init(0);
var freelist_buf: [FREELIST_CAP]u64 = undefined;
var freelist_top: usize = 0;
var freelist_lock: SpinLock = .{};

pub const Stack = struct {
    top: VAddr,
    base: VAddr,
    guard: VAddr,
    slot: u64,
};

pub const KernelStackPage = enum { usable, guard, not_stack };

pub fn isKernelStackPage(vaddr: VAddr) KernelStackPage {
    if (vaddr.addr < STACK_RANGE_START or vaddr.addr >= STACK_RANGE_END) return .not_stack;
    const slot_offset = (vaddr.addr - STACK_RANGE_START) % SLOT_SIZE;
    if (slot_offset == 0) return .guard;
    return .usable;
}

pub fn lookupGuard(pid: u64, vaddr: VAddr) void {
    _ = pid;
    _ = vaddr;
}

fn allocSlot() !u64 {
    freelist_lock.lock();
    if (freelist_top > 0) {
        freelist_top -= 1;
        const slot = freelist_buf[freelist_top];
        freelist_lock.unlock();
        return slot;
    }
    freelist_lock.unlock();

    const slot = next_slot.fetchAdd(1, .monotonic);
    if (slot >= MAX_SLOTS) return error.OutOfKernelStacks;
    return slot;
}

fn recycleSlot(slot: u64) void {
    freelist_lock.lock();
    defer freelist_lock.unlock();
    if (freelist_top < FREELIST_CAP) {
        freelist_buf[freelist_top] = slot;
        freelist_top += 1;
    }
}

pub fn createKernel() !Stack {
    const slot = try allocSlot();
    const guard_addr = STACK_RANGE_START + slot * SLOT_SIZE;
    return .{
        .guard = VAddr.fromInt(guard_addr),
        .base = VAddr.fromInt(guard_addr + paging.PAGE4K),
        .top = VAddr.fromInt(guard_addr + SLOT_SIZE),
        .slot = slot,
    };
}

pub fn destroyKernel(stack: Stack, addr_space_root: PAddr) void {
    var page_addr = stack.base.addr;
    while (page_addr < stack.top.addr) : (page_addr += paging.PAGE4K) {
        if (arch.unmapPage(addr_space_root, VAddr.fromInt(page_addr))) |paddr| {
            const pmm_iface = pmm.global_pmm.?.allocator();
            const page: *paging.PageMem(.page4k) = @ptrFromInt(VAddr.fromPAddr(paddr, null).addr);
            pmm_iface.destroy(page);
        }
    }
    recycleSlot(stack.slot);
}

pub fn createUser(proc_vmm: *zag.memory.vmm.VirtualMemoryManager, num_pages: u32) !Stack {
    const result = try proc_vmm.reserveStack(num_pages);
    return .{
        .top = result.top,
        .base = result.base,
        .guard = result.guard,
        .slot = std.math.maxInt(u64),
    };
}

pub fn destroyUser(stack: Stack, proc_vmm: *zag.memory.vmm.VirtualMemoryManager) void {
    proc_vmm.reclaimStack(stack);
}

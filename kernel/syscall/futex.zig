const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const futex = zag.proc.futex;
const sched = zag.sched.scheduler;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const E_BADADDR = errors.E_BADADDR;
const E_INVAL = errors.E_INVAL;

const MAX_FUTEX_ADDRS = 64;

pub fn sysFutexWaitVal(addrs_ptr: u64, expected_ptr: u64, count: u64, timeout_ns: u64) i64 {
    if (count == 0 or count > MAX_FUTEX_ADDRS) return E_INVAL;

    const proc = sched.currentProc();
    const thread = sched.currentThread().?;
    const cnt: usize = @intCast(count);

    // Read user addresses and expected values, resolve to physical.
    var paddrs: [MAX_FUTEX_ADDRS]PAddr = undefined;
    var expected: [MAX_FUTEX_ADDRS]u64 = undefined;

    for (0..cnt) |i| {
        const addr_va = addrs_ptr + i * 8;
        const exp_va = expected_ptr + i * 8;

        // Read the user address value.
        proc.vmm.demandPage(VAddr.fromInt(addr_va), false, false) catch return E_BADADDR;
        const addr_page = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(addr_va)) orelse return E_BADADDR;
        const addr_physmap = VAddr.fromPAddr(addr_page, null).addr + (addr_va & 0xFFF);
        const user_addr = @as(*const u64, @ptrFromInt(addr_physmap)).*;

        if (!std.mem.isAligned(user_addr, 8)) return E_INVAL;

        // Read the expected value.
        proc.vmm.demandPage(VAddr.fromInt(exp_va), false, false) catch return E_BADADDR;
        const exp_page = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(exp_va)) orelse return E_BADADDR;
        const exp_physmap = VAddr.fromPAddr(exp_page, null).addr + (exp_va & 0xFFF);
        expected[i] = @as(*const u64, @ptrFromInt(exp_physmap)).*;

        // Resolve the target futex address to physical.
        proc.vmm.demandPage(VAddr.fromInt(user_addr), false, false) catch return E_BADADDR;
        const page_paddr = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(user_addr)) orelse return E_BADADDR;
        paddrs[i] = PAddr.fromInt(page_paddr.addr + (user_addr & 0xFFF));
    }

    if (cnt == 1) {
        return futex.wait(paddrs[0], expected[0], timeout_ns, thread);
    }
    return futex.waitVal(paddrs[0..cnt], expected[0..cnt], cnt, timeout_ns, thread);
}

pub fn sysFutexWaitChange(addrs_ptr: u64, count: u64, timeout_ns: u64) i64 {
    if (count == 0 or count > MAX_FUTEX_ADDRS) return E_INVAL;

    const proc = sched.currentProc();
    const thread = sched.currentThread().?;
    const cnt: usize = @intCast(count);

    var paddrs: [MAX_FUTEX_ADDRS]PAddr = undefined;

    for (0..cnt) |i| {
        const addr_va = addrs_ptr + i * 8;

        // Read the user address value.
        proc.vmm.demandPage(VAddr.fromInt(addr_va), false, false) catch return E_BADADDR;
        const addr_page = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(addr_va)) orelse return E_BADADDR;
        const addr_physmap = VAddr.fromPAddr(addr_page, null).addr + (addr_va & 0xFFF);
        const user_addr = @as(*const u64, @ptrFromInt(addr_physmap)).*;

        if (!std.mem.isAligned(user_addr, 8)) return E_INVAL;

        // Resolve the target futex address to physical.
        proc.vmm.demandPage(VAddr.fromInt(user_addr), false, false) catch return E_BADADDR;
        const page_paddr = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(user_addr)) orelse return E_BADADDR;
        paddrs[i] = PAddr.fromInt(page_paddr.addr + (user_addr & 0xFFF));
    }

    return futex.waitChange(paddrs[0..cnt], cnt, timeout_ns, thread);
}

pub fn sysFutexWake(addr: u64, count: u64) i64 {
    if (!std.mem.isAligned(addr, 8)) return E_INVAL;

    const proc = sched.currentProc();
    const vaddr = VAddr.fromInt(addr);
    const page_paddr = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse return E_BADADDR;
    const paddr = PAddr.fromInt(page_paddr.addr + (addr & 0xFFF));

    return @intCast(futex.wake(paddr, @truncate(count)));
}

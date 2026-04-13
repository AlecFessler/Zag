const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
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

    // Bound and wrap-check the two user arrays before touching them.
    // Without this, an addrs_ptr near ~0 wraps into the low half on each
    // iteration and bypasses any partition check.
    const total_bytes = cnt * 8;
    const addrs_end = std.math.add(u64, addrs_ptr, total_bytes) catch return E_BADADDR;
    const expected_end = std.math.add(u64, expected_ptr, total_bytes) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(addrs_ptr) or
        !address.AddrSpacePartition.user.contains(addrs_end - 1)) return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(expected_ptr) or
        !address.AddrSpacePartition.user.contains(expected_end - 1)) return E_BADADDR;

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
        if (!address.AddrSpacePartition.user.contains(user_addr)) return E_BADADDR;

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
        const result = futex.wait(paddrs[0], expected[0], timeout_ns, thread);
        // futex.wait returns E_AGAIN on mismatch; convert to index 0 per spec.
        return if (result == futex.E_AGAIN) 0 else result;
    }
    return futex.waitVal(paddrs[0..cnt], expected[0..cnt], cnt, timeout_ns, thread);
}

pub fn sysFutexWaitChange(addrs_ptr: u64, count: u64, timeout_ns: u64) i64 {
    if (count == 0 or count > MAX_FUTEX_ADDRS) return E_INVAL;

    const proc = sched.currentProc();
    const thread = sched.currentThread().?;
    const cnt: usize = @intCast(count);

    const total_bytes = cnt * 8;
    const addrs_end = std.math.add(u64, addrs_ptr, total_bytes) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(addrs_ptr) or
        !address.AddrSpacePartition.user.contains(addrs_end - 1)) return E_BADADDR;

    var paddrs: [MAX_FUTEX_ADDRS]PAddr = undefined;

    for (0..cnt) |i| {
        const addr_va = addrs_ptr + i * 8;

        // Read the user address value.
        proc.vmm.demandPage(VAddr.fromInt(addr_va), false, false) catch return E_BADADDR;
        const addr_page = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(addr_va)) orelse return E_BADADDR;
        const addr_physmap = VAddr.fromPAddr(addr_page, null).addr + (addr_va & 0xFFF);
        const user_addr = @as(*const u64, @ptrFromInt(addr_physmap)).*;

        if (!std.mem.isAligned(user_addr, 8)) return E_INVAL;
        if (!address.AddrSpacePartition.user.contains(user_addr)) return E_BADADDR;

        // Resolve the target futex address to physical.
        proc.vmm.demandPage(VAddr.fromInt(user_addr), false, false) catch return E_BADADDR;
        const page_paddr = arch.resolveVaddr(proc.addr_space_root, VAddr.fromInt(user_addr)) orelse return E_BADADDR;
        paddrs[i] = PAddr.fromInt(page_paddr.addr + (user_addr & 0xFFF));
    }

    return futex.waitChange(paddrs[0..cnt], cnt, timeout_ns, thread);
}

pub fn sysFutexWake(addr: u64, count: u64) i64 {
    if (!std.mem.isAligned(addr, 8)) return E_INVAL;
    // Without a user-partition check, a malicious caller could pass a
    // kernel VA and use the E_BADADDR / success distinction as a KASLR
    // oracle — and would also feed arbitrary kernel paddrs into futex
    // bucket lookups.
    if (!address.AddrSpacePartition.user.contains(addr)) return E_BADADDR;

    const proc = sched.currentProc();
    const vaddr = VAddr.fromInt(addr);
    const page_paddr = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse return E_BADADDR;
    const paddr = PAddr.fromInt(page_paddr.addr + (addr & 0xFFF));

    return @intCast(futex.wake(paddr, @truncate(count)));
}

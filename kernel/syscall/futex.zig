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

pub fn sysFutexWait(addr: u64, expected: u64, timeout_ns: u64) i64 {
    if (!std.mem.isAligned(addr, 8)) return E_INVAL;

    const proc = sched.currentProc();
    const vaddr = VAddr.fromInt(addr);
    const page_paddr = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse return E_BADADDR;
    const paddr = PAddr.fromInt(page_paddr.addr + (addr & 0xFFF));

    return futex.wait(paddr, expected, timeout_ns, sched.currentThread().?);
}

pub fn sysFutexWake(addr: u64, count: u64) i64 {
    if (!std.mem.isAligned(addr, 8)) return E_INVAL;

    const proc = sched.currentProc();
    const vaddr = VAddr.fromInt(addr);
    const page_paddr = arch.resolveVaddr(proc.addr_space_root, vaddr) orelse return E_BADADDR;
    const paddr = PAddr.fromInt(page_paddr.addr + (addr & 0xFFF));

    return @intCast(futex.wake(paddr, @truncate(count)));
}

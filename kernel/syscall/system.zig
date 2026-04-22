const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const kprof_dump = zag.kprof.dump;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;

const VAddr = zag.memory.address.VAddr;

const E_AGAIN = errors.E_AGAIN;
const E_BADADDR = errors.E_BADADDR;
const E_INVAL = errors.E_INVAL;
const E_OK = errors.E_OK;
const E_PERM = errors.E_PERM;

const CpuPowerAction = zag.arch.dispatch.power.CpuPowerAction;
const PowerAction = zag.arch.dispatch.power.PowerAction;
const SyscallResult = zag.syscall.dispatch.SyscallResult;

pub fn sysWrite(ptr: u64, len: u64) SyscallResult {
    if (len == 0) return .{ .ret = 0 };
    if (len > 4096) return .{ .ret = E_INVAL };
    if (!address.AddrSpacePartition.user.contains(ptr)) return .{ .ret = E_BADADDR };
    const end = std.math.add(u64, ptr, len) catch return .{ .ret = E_BADADDR };
    if (!address.AddrSpacePartition.user.contains(end -| 1)) return .{ .ret = E_BADADDR };
    // SMAP: print reads the user buffer while formatting, so the AC=1
    // window must span the entire print call rather than just the slice
    // construction.
    arch.interrupts.userAccessBegin();
    const msg: []const u8 = @as([*]const u8, @ptrFromInt(ptr))[0..len];
    arch.boot.print("{s}", .{msg});
    arch.interrupts.userAccessEnd();
    return .{ .ret = @intCast(len) };
}

pub fn sysGetrandom(buf_ptr: u64, len: u64) i64 {
    if (len == 0 or len > 4096) return E_INVAL;

    // Validate buffer address range.
    if (!address.AddrSpacePartition.user.contains(buf_ptr)) return E_BADADDR;
    const end = std.math.add(u64, buf_ptr, len) catch return E_BADADDR;
    if (!address.AddrSpacePartition.user.contains(end -| 1)) return E_BADADDR;

    const proc = sched.currentProc();
    var remaining: u64 = len;
    var dst_va: u64 = buf_ptr;

    while (remaining > 0) {
        const rand_val = arch.power.getRandom() orelse {
            // If we haven't written anything yet, return E_AGAIN.
            if (remaining == len) return E_AGAIN;
            // Otherwise return E_AGAIN (partial fill not supported).
            return E_AGAIN;
        };

        const page_off = dst_va & 0xFFF;
        const chunk = @min(remaining, 8);
        const page_chunk = @min(chunk, paging.PAGE4K - page_off);

        // Demand-page the destination.
        proc.vmm.demandPage(VAddr.fromInt(dst_va), true, false) catch return E_BADADDR;
        const page_paddr = arch.paging.resolveVaddr(proc.addr_space_root, VAddr.fromInt(dst_va)) orelse return E_BADADDR;
        const physmap_addr = VAddr.fromPAddr(page_paddr, null).addr + page_off;

        const bytes: [8]u8 = @bitCast(rand_val);
        const write_len = @min(page_chunk, chunk);
        const dst: [*]u8 = @ptrFromInt(physmap_addr);
        @memcpy(dst[0..write_len], bytes[0..write_len]);

        dst_va += write_len;
        remaining -= write_len;
    }

    return E_OK;
}

pub fn sysSysPower(action_raw: u64) i64 {
    const proc = sched.currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().power) return E_PERM;

    const action = std.meta.intToEnum(PowerAction, @as(u8, @truncate(action_raw))) catch return E_INVAL;
    // Kernel profiling: root exiting the system is our cue to flush the
    // trace/sample log to serial before the machine powers off.
    if (action == .shutdown or action == .reboot) {
        kprof_dump.end(.root_exit);
    }
    return arch.power.powerAction(action);
}

pub fn sysSysCpuPower(action_raw: u64, value: u64) i64 {
    const proc = sched.currentProc();
    const self_entry = proc.getPermByHandle(0) orelse return E_PERM;
    if (!self_entry.processRights().power) return E_PERM;

    const action = std.meta.intToEnum(CpuPowerAction, @as(u8, @truncate(action_raw))) catch return E_INVAL;
    return arch.power.cpuPowerAction(action, value);
}

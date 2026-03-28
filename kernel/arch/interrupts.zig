const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const aarch64 = zag.arch.aarch64;
const address = zag.memory.address;
const arch = zag.arch.dispatch;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const scheduler = zag.sched.scheduler;
const stack_mod = zag.memory.stack;
const x64 = zag.arch.x64;

const CrashReason = zag.perms.permissions.CrashReason;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

pub const ArchCpuContext = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.ArchCpuContext,
    .aarch64 => aarch64.interrupts.ArchCpuContext,
    else => unreachable,
};

pub const PageFaultContext = switch (builtin.cpu.arch) {
    .x86_64 => x64.interrupts.PageFaultContext,
    .aarch64 => aarch64.interrupts.PageFaultContext,
    else => unreachable,
};

const KERNEL_PERMS = MemoryPerms{
    .write_perm = .write,
    .execute_perm = .no_execute,
    .cache_perm = .write_back,
    .global_perm = .global,
    .privilege_perm = .kernel,
};

fn demandPageKernel(faulting_virt: VAddr) void {
    const page_base = VAddr.fromInt(std.mem.alignBackward(u64, faulting_virt.addr, paging.PAGE4K));
    const kroot = memory_init.kernel_addr_space_root;

    if (arch.resolveVaddr(kroot, page_base) != null) return;

    const pmm_iface = pmm.global_pmm.?.allocator();
    const page = pmm_iface.create(paging.PageMem(.page4k)) catch
        @panic("OOM in kernel demand page fault");
    @memset(std.mem.asBytes(page), 0);

    const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
    arch.mapPage(kroot, phys, page_base, KERNEL_PERMS) catch
        @panic("mapPage failed in kernel demand page fault");
}

fn accessReason(is_write: bool, is_exec: bool) CrashReason {
    if (is_exec) return .invalid_execute;
    if (is_write) return .invalid_write;
    return .invalid_read;
}

fn guardPageReason(proc: anytype, node_start: u64) CrashReason {
    const above = proc.vmm.findNode(VAddr.fromInt(node_start + paging.PAGE4K));
    if (above != null and above.?.rights.write) {
        return .stack_overflow;
    }
    return .stack_underflow;
}

pub fn handlePageFault(fault: *const PageFaultContext) void {
    const faulting_virt = VAddr.fromInt(fault.faulting_address);
    const is_kernel_privilege = fault.is_kernel_privilege;
    const is_user_va = faulting_virt.addr < address.AddrSpacePartition.user.end;
    const is_write = fault.is_write;
    const is_exec = fault.is_exec;

    if (is_kernel_privilege) {
        if (is_user_va) {
            const thread = scheduler.currentThread() orelse @panic("kernel page fault on user VA with no current thread");
            arch.print("K: PAGEFAULT pid={d} addr=0x{x} w={} x={}\n", .{ thread.process.pid, fault.faulting_address, is_write, is_exec });
            thread.process.kill(accessReason(is_write, is_exec));
            arch.enableInterrupts();
            while (true) arch.halt();
        }

        switch (stack_mod.isKernelStackPage(faulting_virt)) {
            .usable => {
                demandPageKernel(faulting_virt);
                return;
            },
            .guard => @panic("Kernel stack overflow"),
            .not_stack => {},
        }

        const ka = address.KernelVA.KernelAllocators.range;
        if (faulting_virt.addr >= ka.start and faulting_virt.addr < ka.end) {
            demandPageKernel(faulting_virt);
            return;
        }

        arch.print("KERNEL PAGE FAULT at 0x{x} (write={} exec={})\n", .{ faulting_virt.addr, is_write, is_exec });
        @panic("unexpected kernel page fault");
    }

    const thread = scheduler.currentThread() orelse @panic("user page fault with no current thread");
    const proc = thread.process;

    const node = proc.vmm.findNode(faulting_virt) orelse {
        arch.print("K: USER_PF pid={d} addr=0x{x} w={} x={}\n", .{ proc.pid, faulting_virt.addr, is_write, is_exec });
        proc.kill(.unmapped_access);
        arch.enableInterrupts();
        while (true) arch.halt();
    };

    switch (node.kind) {
        .shared_memory, .mmio => {
            proc.kill(accessReason(is_write, is_exec));
            arch.enableInterrupts();
            while (true) arch.halt();
        },
        .private => {
            const rights_ok = blk: {
                if (is_exec) break :blk node.rights.execute;
                if (is_write) break :blk node.rights.write;
                break :blk node.rights.read;
            };

            if (!rights_ok) {
                if (!node.rights.read and !node.rights.write and !node.rights.execute and node.size == paging.PAGE4K) {
                    proc.kill(guardPageReason(proc, node.start.addr));
                } else {
                    proc.kill(accessReason(is_write, is_exec));
                }
                arch.enableInterrupts();
                while (true) arch.halt();
            }

            const page_base = VAddr.fromInt(std.mem.alignBackward(u64, faulting_virt.addr, paging.PAGE4K));
            if (arch.resolveVaddr(proc.addr_space_root, page_base) != null) {
                @panic("user fault on already-mapped page");
            }

            proc.vmm.demandPage(faulting_virt, is_write, is_exec) catch {
                proc.kill(.out_of_memory);
                arch.enableInterrupts();
                while (true) arch.halt();
            };
        },
    }
}

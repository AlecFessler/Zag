const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const kprof = zag.kprof.trace_id;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const scheduler = zag.sched.scheduler;
const stack_mod = zag.memory.stack;

const FaultReason = zag.perms.permissions.FaultReason;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFaultContext = zag.arch.dispatch.cpu.PageFaultContext;
const VAddr = zag.memory.address.VAddr;

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

    if (arch.paging.resolveVaddr(kroot, page_base) != null) return;

    const pmm_iface = pmm.global_pmm.?.allocator();
    const page = pmm_iface.create(paging.PageMem(.page4k)) catch
        @panic("OOM in kernel demand page fault");
    @memset(std.mem.asBytes(page), 0);

    const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
    arch.paging.mapPage(kroot, phys, page_base, KERNEL_PERMS) catch
        @panic("mapPage failed in kernel demand page fault");
}

fn accessReason(is_write: bool, is_exec: bool) FaultReason {
    if (is_exec) return .invalid_execute;
    if (is_write) return .invalid_write;
    return .invalid_read;
}

fn guardPageReason(proc: anytype, node_start: u64) FaultReason {
    const above = proc.vmm.findNode(VAddr.fromInt(node_start + paging.PAGE4K));
    if (above != null and above.?.rights.write) {
        return .stack_overflow;
    }
    return .stack_underflow;
}

pub fn handlePageFault(fault: *const PageFaultContext) void {
    kprof.enter(.handle_page_fault);
    defer kprof.exit(.handle_page_fault);
    kprof.point(.handle_page_fault, fault.faulting_address);
    const faulting_virt = VAddr.fromInt(fault.faulting_address);
    const is_kernel_privilege = fault.is_kernel_privilege;
    const is_user_va = faulting_virt.addr < address.AddrSpacePartition.user.end;
    const is_write = fault.is_write;
    const is_exec = fault.is_exec;

    if (is_kernel_privilege and is_user_va) {
        const thread = scheduler.currentThread() orelse @panic("kernel page fault on user VA with no current thread");
        arch.boot.print("K: PAGEFAULT pid={d} addr=0x{x} w={} x={} rip=0x{x}\n", .{ thread.process.pid, fault.faulting_address, is_write, is_exec, fault.rip });
        thread.process.kill(accessReason(is_write, is_exec));
        arch.interrupts.enableInterrupts();
        while (true) arch.cpu.halt();
    }

    if (is_kernel_privilege) {
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

        arch.boot.print("KERNEL PAGE FAULT at 0x{x} (write={} exec={})\n", .{ faulting_virt.addr, is_write, is_exec });
        @panic("unexpected kernel page fault");
    }

    const thread = scheduler.currentThread() orelse @panic("user page fault with no current thread");
    const proc = thread.process;

    const node = proc.vmm.findNode(faulting_virt) orelse {
        arch.boot.print("K: USER_PF pid={d} addr=0x{x} w={} x={}\n", .{ proc.pid, faulting_virt.addr, is_write, is_exec });
        if (proc.faultBlock(thread, .unmapped_access, faulting_virt.addr, fault.rip, fault.user_ctx)) {
            arch.interrupts.enableInterrupts();
            scheduler.yield();
            return;
        }
        proc.kill(.unmapped_access);
        arch.interrupts.enableInterrupts();
        while (true) arch.cpu.halt();
    };

    switch (node.kind) {
        .shared_memory, .mmio => {
            const r = accessReason(is_write, is_exec);
            if (proc.faultBlock(thread, r, faulting_virt.addr, fault.rip, fault.user_ctx)) {
                arch.interrupts.enableInterrupts();
                scheduler.yield();
                return;
            }
            proc.kill(r);
            arch.interrupts.enableInterrupts();
            while (true) arch.cpu.halt();
        },
        .virtual_bar => {
            // Virtual BAR faults should be intercepted by the arch-specific
            // page fault handler. Reaching here means something unexpected
            // happened (e.g., present-page protection fault).
            if (proc.faultBlock(thread, .protection_fault, faulting_virt.addr, fault.rip, fault.user_ctx)) {
                arch.interrupts.enableInterrupts();
                scheduler.yield();
                return;
            }
            proc.kill(.protection_fault);
            arch.interrupts.enableInterrupts();
            while (true) arch.cpu.halt();
        },
        .private => {
            const rights_ok = blk: {
                if (is_exec) break :blk node.rights.execute;
                if (is_write) break :blk node.rights.write;
                break :blk node.rights.read;
            };

            if (!rights_ok) {
                const r2 = if (!node.rights.read and !node.rights.write and !node.rights.execute and node.size == paging.PAGE4K)
                    guardPageReason(proc, node.start.addr)
                else
                    accessReason(is_write, is_exec);
                if (proc.faultBlock(thread, r2, faulting_virt.addr, fault.rip, fault.user_ctx)) {
                    arch.interrupts.enableInterrupts();
                    scheduler.yield();
                    return;
                }
                proc.kill(r2);
                arch.interrupts.enableInterrupts();
                while (true) arch.cpu.halt();
            }

            // Note: we do NOT pre-check arch.paging.resolveVaddr here. A concurrent
            // syscall pre-fault on another CPU (readUserBytes, vmRecv, futex,
            // sysinfo, pmu, proc_create, vCPU run) can install the PTE
            // between the hardware raising #PF and us reaching this point.
            // demandPage takes vmm.lock and has an "already backed" fast
            // path, so the benign race becomes a silent no-op and the
            // faulting instruction simply retries.
            proc.vmm.demandPage(faulting_virt, is_write, is_exec) catch {
                if (proc.faultBlock(thread, .out_of_memory, faulting_virt.addr, fault.rip, fault.user_ctx)) {
                    arch.interrupts.enableInterrupts();
                    scheduler.yield();
                    return;
                }
                proc.kill(.out_of_memory);
                arch.interrupts.enableInterrupts();
                while (true) arch.cpu.halt();
            };
        },
    }
}

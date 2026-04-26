const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const kprof = zag.kprof.trace_id;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const port = zag.sched.port;
const scheduler = zag.sched.scheduler;
const stack_mod = zag.memory.stack;
const var_range = zag.capdom.var_range;

const MemoryPerms = zag.memory.address.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PageFaultContext = zag.arch.dispatch.cpu.PageFaultContext;
const VAddr = zag.memory.address.VAddr;

/// Memory-fault sub-code carried in the event payload alongside
/// `EventType.memory_fault` per spec §[event_type] table 1840 ("invalid
/// read/write/execute, unmapped access, protection violation").
const MemoryFaultSubcode = enum(u8) {
    unmapped = 0,
    invalid_read = 1,
    invalid_write = 2,
    invalid_execute = 3,
    protection_fault = 4,
};

const KERNEL_PERMS = MemoryPerms{
    .read = true,
    .write = true,
    .exec = false,
};

fn demandPageKernel(faulting_virt: VAddr) void {
    const page_base = VAddr.fromInt(std.mem.alignBackward(u64, faulting_virt.addr, paging.PAGE4K));
    const kroot = memory_init.kernel_addr_space_root;

    if (arch.paging.resolveVaddr(kroot, page_base) != null) return;

    const pmm_mgr = &pmm.global_pmm.?;
    const page = pmm_mgr.create(paging.PageMem(.page4k)) catch
        @panic("OOM in kernel demand page fault");

    const phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(page)), null);
    arch.paging.mapPage(kroot, phys, page_base, KERNEL_PERMS) catch
        @panic("mapPage failed in kernel demand page fault");
}

/// Translate (is_write, is_exec) into the rwx triple consumed by
/// `var_range.handlePageFault` (R=1, W=2, X=4 per spec §[var]).
fn accessRwx(is_write: bool, is_exec: bool) u3 {
    if (is_exec) return 0b100;
    if (is_write) return 0b010;
    return 0b001;
}

fn accessSubcode(is_write: bool, is_exec: bool) MemoryFaultSubcode {
    if (is_exec) return .invalid_execute;
    if (is_write) return .invalid_write;
    return .invalid_read;
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
        // Kernel touched a user VA via a syscall accessor — surface as a
        // memory_fault on the EC whose syscall triggered the access.
        const ec = scheduler.currentEc() orelse
            @panic("kernel page fault on user VA with no current EC");
        port.fireMemoryFault(ec, @intFromEnum(accessSubcode(is_write, is_exec)), faulting_virt.addr);
        arch.cpu.enableInterrupts();
        scheduler.yieldTo(null);
        return;
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

    const ec = scheduler.currentEc() orelse
        @panic("user page fault with no current EC");

    const dom_ref = ec.domain;
    const dom = dom_ref.lock(@src()) catch {
        // Domain torn down between exception entry and here — fire
        // memory_fault so the no-route fallback retires the EC.
        port.fireMemoryFault(ec, @intFromEnum(MemoryFaultSubcode.unmapped), faulting_virt.addr);
        arch.cpu.enableInterrupts();
        scheduler.yieldTo(null);
        return;
    };

    const rc = var_range.handlePageFault(dom, faulting_virt, accessRwx(is_write, is_exec));
    dom_ref.unlock();

    // Spec v3 var_range.handlePageFault returns 0 on a resolved fault
    // (demand alloc, MMIO/port-IO virtualization, etc.). Any non-zero
    // return — E_BADADDR (no covering VAR), E_PERM (rights mismatch),
    // E_NOMEM (demand alloc exhausted) — routes through the EC's
    // memory_fault event. fireMemoryFault either suspends the EC on the
    // bound port or applies the no-route fallback (restart or destroy
    // the owning domain) per spec §[event_route]. Either outcome leaves
    // this EC unrunnable, so yield the CPU after firing.
    if (rc != 0) {
        const subcode = if (rc == zag.syscall.errors.E_BADADDR)
            MemoryFaultSubcode.unmapped
        else
            accessSubcode(is_write, is_exec);
        port.fireMemoryFault(ec, @intFromEnum(subcode), faulting_virt.addr);
        arch.cpu.enableInterrupts();
        scheduler.yieldTo(null);
    }
}

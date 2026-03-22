const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const address = zag.memory.address;
const arch = zag.arch.dispatch;
const aarch64 = zag.arch.aarch64;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;
const stack_mod = zag.memory.stack;
const x64 = zag.arch.x64;

const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PrivilegePerm = zag.perms.privilege.PrivilegePerm;
const VAddr = zag.memory.address.VAddr;

pub const ArchCpuContext = switch (builtin.cpu.arch) {
    .x86_64 => x64.cpu.Context,
    .aarch64 => aarch64.cpu.Context,
    else => unreachable,
};

pub const PageFaultContext = struct {
    privilege: PrivilegePerm,
    faulting_virt: VAddr,
    present: bool,
    fetch: bool,
    write: bool,
};

pub fn pageFaultHandler(ctx: PageFaultContext) void {
    const faulting_page_virt = VAddr.fromInt(std.mem.alignBackward(
        u64,
        ctx.faulting_virt.addr,
        paging.PAGE4K,
    ));

    if (ctx.privilege == .kernel) {
        if (address.AddrSpacePartition.user.contains(ctx.faulting_virt.addr)) {
            if (sched.initialized) {
                if (sched.currentThread()) |thread| {
                    thread.process.kill();
                    while (true) {
                        arch.enableInterrupts();
                        asm volatile ("hlt");
                    }
                }
            }
            @panic("Ring 0 fault on user VA without current thread");
        }

        switch (stack_mod.isKernelStackPage(ctx.faulting_virt)) {
            .usable => {
                if (pmm.global_pmm == null) {
                    @panic("Page fault prior to pmm initialization");
                }
                const phys_page = pmm.global_pmm.?.allocator().create(paging.PageMem(.page4k)) catch @panic("PMM OOM!");
                @memset(&phys_page.mem, 0);
                const phys_page_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(phys_page)), null);
                arch.mapPage(
                    arch.getAddrSpaceRoot(),
                    phys_page_phys,
                    faulting_page_virt,
                    .{ .write_perm = .write, .execute_perm = .no_execute, .cache_perm = .write_back, .global_perm = .global, .privilege_perm = .kernel },
                ) catch @panic("Failed to map kernel stack page");
                return;
            },
            .guard => @panic("Kernel stack overflow"),
            .not_stack => @panic("Kernel page fault in non-stack region"),
        }
    }

    if (pmm.global_pmm == null) {
        @panic("Page fault prior to pmm initialization");
    }

    if (!sched.initialized) @panic("User page fault before scheduler initialized");

    const thread = sched.currentThread() orelse @panic("User page fault with no current thread");
    const proc = thread.process;

    const node = proc.vmm.findNode(ctx.faulting_virt) orelse {
        _ = stack_mod.lookupGuard(proc.pid, ctx.faulting_virt);
        proc.kill();
        while (true) {
            arch.enableInterrupts();
            asm volatile ("hlt");
        }
    };

    switch (node.node_type) {
        .shared_memory, .mmio => {
            _ = stack_mod.lookupGuard(proc.pid, ctx.faulting_virt);
            proc.kill();
            while (true) {
                arch.enableInterrupts();
                asm volatile ("hlt");
            }
        },
        .private => {
            const access_ok = blk: {
                if (ctx.fetch) break :blk node.current_rights.execute;
                if (ctx.write) break :blk node.current_rights.write;
                break :blk node.current_rights.read;
            };

            if (!access_ok or ctx.present) {
                _ = stack_mod.lookupGuard(proc.pid, ctx.faulting_virt);
                proc.kill();
                while (true) {
                    arch.enableInterrupts();
                    asm volatile ("hlt");
                }
            }

            const phys_page = pmm.global_pmm.?.allocator().create(paging.PageMem(.page4k)) catch @panic("PMM OOM!");
            @memset(&phys_page.mem, 0);
            const phys_page_phys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(phys_page)), null);
            const page_perms: MemoryPerms = .{
                .write_perm = if (node.current_rights.write) .write else .no_write,
                .execute_perm = if (node.current_rights.execute) .execute else .no_execute,
                .cache_perm = .write_back,
                .global_perm = .not_global,
                .privilege_perm = .user,
            };
            arch.mapPage(
                proc.addr_space_root,
                phys_page_phys,
                faulting_page_virt,
                page_perms,
            ) catch @panic("Failed to map page in page fault handler");
        },
    }
}

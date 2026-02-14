const builtin = @import("builtin");
const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const aarch64 = zag.arch.aarch64;
const paging = zag.memory.paging;
const process = zag.sched.process;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;
const x64 = zag.arch.x64;

const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const PrivilegePerm = zag.perms.privilege.PrivilegePerm;
const VAddr = zag.memory.address.VAddr;
const VmReservation = zag.memory.vmm.VmReservation;

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
    if (pmm.global_pmm == null) {
        @panic("Page fault prior to pmm initialization");
    }
    const pmm_iface = pmm.global_pmm.?.allocator();

    const faulting_page_virt = VAddr.fromInt(std.mem.alignBackward(
        u64,
        ctx.faulting_virt.addr,
        @intFromEnum(paging.PageSize.page4k),
    ));

    if (ctx.present) {
        if (ctx.fetch) {
            @panic("Invalid instruction fetch on present page");
        } else if (ctx.write) {
            @panic("Invalid write on present page");
        }
    }

    const kspace_res = process.global_kproc.vmm.findReservation(ctx.faulting_virt);
    const uspace_res: ?*VmReservation = blk: {
        if (sched.initialized) {
            if (sched.currentThread()) |thread| {
                break :blk thread.proc.vmm.findReservation(ctx.faulting_virt);
            }
        }
        break :blk null;
    };

    const res = kspace_res orelse uspace_res orelse
        @panic("Page fault in unreserved address space");

    const page_perms: MemoryPerms = .{
        .write_perm = if (res.rights.write) .write else .no_write,
        .execute_perm = if (res.rights.execute) .execute else .no_execute,
        .cache_perm = .write_back,
        .global_perm = if (kspace_res != null) .global else .not_global,
        .privilege_perm = if (kspace_res != null) .kernel else .user,
    };

    const phys_page = pmm_iface.create(paging.PageMem(.page4k)) catch @panic("PMM OOM!");
    const phys_page_virt = VAddr.fromInt(@intFromPtr(phys_page));
    const phys_page_phys = PAddr.fromVAddr(phys_page_virt, null);

    const addr_space_root_phys = arch.getAddrSpaceRoot();
    const addr_space_root_virt = VAddr.fromPAddr(addr_space_root_phys, null);

    arch.mapPage(
        addr_space_root_virt,
        phys_page_phys,
        faulting_page_virt,
        .page4k,
        page_perms,
        pmm_iface,
    ) catch @panic("Failed to map page in page fault handler");
}

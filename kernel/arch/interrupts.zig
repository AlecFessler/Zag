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

    if (ctx.privilege == .kernel) {
        if (ctx.present) {
            if (ctx.fetch) {
                @panic("Invalid kernel instruction fetch");
            } else if (ctx.write) {
                @panic("Invalid kernel write");
            }
        }
    } else {
        @panic("User page fault: invalid access (process killing not implemented yet)");
    }

    const phys_page = pmm_iface.create(paging.PageMem(.page4k)) catch @panic("PMM OOM!");
    const phys_page_virt = VAddr.fromInt(@intFromPtr(phys_page));
    const phys_page_phys = PAddr.fromVAddr(phys_page_virt, null);

    const addr_space_root_phys = arch.getAddrSpaceRoot();
    const addr_space_root_virt = VAddr.fromPAddr(addr_space_root_phys, null);

    const in_kspace = process.global_kproc.vmm.isValidVAddr(ctx.faulting_virt);
    const in_uspace = blk: {
        if (sched.global_running_thread) |rt| {
            break :blk rt.proc.vmm.isValidVAddr(ctx.faulting_virt);
        } else break :blk false;
    };

    const page_perms: MemoryPerms = blk: {
        if (in_kspace) {
            break :blk .{
                .write_perm = .write,
                .execute_perm = .no_execute,
                .cache_perm = .write_back,
                .global_perm = .global,
                .privilege_perm = .kernel,
            };
        } else if (in_uspace) {
            break :blk .{
                .write_perm = .write,
                .execute_perm = .no_execute,
                .cache_perm = .write_back,
                .global_perm = .not_global,
                .privilege_perm = .user,
            };
        } else {
            @panic("Non-present page in neither kernel or user address space!");
        }
    };

    arch.mapPage(
        addr_space_root_virt,
        phys_page_phys,
        faulting_page_virt,
        .page4k,
        page_perms,
        pmm_iface,
    ) catch @panic("Failed to map page in page fault handler");
}

const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const apic = zag.arch.x64.apic;
const cpu = zag.arch.x64.cpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const pmm = zag.memory.pmm;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;
const timers = zag.arch.x64.timers;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const trampoline_code = @import("embedded_bins").trampoline;

const TrampolineParams = extern struct {
    cr3: u64,
    stack_top: u64,
    entry_point: u64,
};

const TRAMPOLINE_PHYS: u64 = 0x8000;
const TRAMPOLINE_VECTOR: u8 = @intCast(TRAMPOLINE_PHYS >> 12);
const params_offset = trampoline_code.len - @sizeOf(TrampolineParams);

var cores_online: std.atomic.Value(u32) = std.atomic.Value(u32).init(1);

pub fn smpInit() !void {
    for (0..apic.coreCount()) |i| {
        gdt.initForCore(i);
    }

    const trampoline_phys = PAddr.fromInt(TRAMPOLINE_PHYS);
    const trampoline_virt = VAddr.fromInt(TRAMPOLINE_PHYS);
    try arch.mapPage(
        VAddr.fromPAddr(arch.getAddrSpaceRoot(), null),
        trampoline_phys,
        trampoline_virt,
        .page4k,
        .{
            .write_perm = .write,
            .execute_perm = .execute,
            .cache_perm = .write_back,
            .global_perm = .not_global,
            .privilege_perm = .kernel,
        },
        pmm.global_pmm.?.allocator(),
    );

    const dest: [*]u8 = @ptrFromInt(trampoline_virt.addr);
    @memcpy(dest[0..trampoline_code.len], trampoline_code);

    const params: *TrampolineParams = @ptrFromInt(trampoline_virt.addr + params_offset);
    params.cr3 = arch.getAddrSpaceRoot().addr;
    params.entry_point = @intFromPtr(&coreInit);

    var pmm_alloc = pmm.global_pmm.?.allocator();
    const bsp_id = apic.rawApicId();
    var hpet = &timers.hpet_timer;
    const hpet_iface = hpet.timer();
    const STACK_SIZE = paging.PAGE4K * 4;

    for (apic.lapics.?) |la| {
        if (la.apic_id == bsp_id) continue;

        const stack = try pmm_alloc.alignedAlloc(u8, paging.pageAlign(.page4k), STACK_SIZE);
        params.stack_top = @intFromPtr(stack.ptr) + STACK_SIZE - 8;

        const expected = cores_online.load(.acquire);
        apic.sendInitIpi(la.apic_id);

        const start = hpet_iface.now();
        while (hpet_iface.now() - start < 10_000_000) {
            std.atomic.spinLoopHint();
        }

        apic.sendSipi(la.apic_id, TRAMPOLINE_VECTOR);

        const timeout = hpet_iface.now();
        while (cores_online.load(.acquire) == expected) {
            if (hpet_iface.now() - timeout > 100_000_000) {
                arch.print("AP {} failed to start\n", .{la.apic_id});
                break;
            }
            std.atomic.spinLoopHint();
        }
    }

    arch.print("SMP: {}/{} cores online\n", .{ cores_online.load(.acquire), apic.coreCount() });
}

fn coreInit() callconv(.c) noreturn {
    gdt.loadGdt(0);
    gdt.reloadSegments();
    cpu.lidt(&idt.idt_ptr);

    if (apic.x2Apic) {
        _ = cpu.enableX2Apic(@intFromEnum(interrupts.IntVecs.spurious));
    } else {
        apic.enableSpuriousVector(@intFromEnum(interrupts.IntVecs.spurious));
    }

    const core_id = apic.coreID();
    gdt.loadGdt(core_id);
    cpu.ltr(gdt.TSS_OFFSET);

    arch.print("AP core {} online\n", .{core_id});
    _ = cores_online.fetchAdd(1, .release);

    sched.perCoreInit();
    arch.halt();
}

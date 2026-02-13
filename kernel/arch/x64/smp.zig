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
const timers = zag.arch.x64.timers;

const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const trampoline_code = @embedFile("trampoline.bin");

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
    const bsp_id = apic.coreID();

    var hpet = &timers.hpet_timer;
    const hpet_iface = hpet.timer();

    const STACK_SIZE = paging.PAGE4K * 4;

    for (apic.lapics, 0..) |la, i| {
        if (la.apic_id == bsp_id) continue;
        arch.print("smp: booting AP {} (apic_id={})\n", .{ i, la.apic_id });

        const stack = try pmm_alloc.alignedAlloc(u8, paging.pageAlign(.page4k), STACK_SIZE);
        params.stack_top = @intFromPtr(stack.ptr) + STACK_SIZE - 8;

        arch.print("smp: stack_top=0x{x}\n", .{params.stack_top});

        const expected = cores_online.load(.acquire);
        apic.sendInitIpi(la.apic_id);

        arch.print("smp: INIT sent\n", .{});
        const start = hpet_iface.now();
        while (hpet_iface.now() - start < 10_000_000) {
            std.atomic.spinLoopHint();
        }

        apic.sendSipi(la.apic_id, TRAMPOLINE_VECTOR);
        arch.print("smp: SIPI sent\n", .{});

        const timeout = hpet_iface.now();
        while (cores_online.load(.acquire) == expected) {
            if (hpet_iface.now() - timeout > 100_000_000) {
                arch.print("AP {} failed to start\n", .{la.apic_id});
                break;
            }
            std.atomic.spinLoopHint();
        }
        arch.print("smp: AP {} done\n", .{la.apic_id});
    }
    arch.print("SMP: {}/{} cores online\n", .{ cores_online.load(.acquire), apic.coreCount() });
}

fn coreInit() callconv(.c) noreturn {
    cpu.lgdt(&gdt.gdt_ptr);
    asm volatile (
        \\pushq %[cs_sel]
        \\leaq 1f(%%rip), %%rax
        \\pushq %%rax
        \\lretq
        \\1:
        \\movw %[ds_sel], %%ax
        \\movw %%ax, %%ds
        \\movw %%ax, %%es
        \\movw %%ax, %%ss
        :
        : [cs_sel] "i" (gdt.KERNEL_CODE_OFFSET),
          [ds_sel] "i" (gdt.KERNEL_DATA_OFFSET),
        : .{ .rax = true, .ax = true, .memory = true }
    );
    cpu.lidt(&idt.idt_ptr);

    if (apic.x2Apic) {
        _ = cpu.enableX2Apic(@intFromEnum(interrupts.IntVecs.spurious));
    } else {
        apic.spurious_int_vec.* = .{
            .spurious_vector = @intFromEnum(interrupts.IntVecs.spurious),
            .apic_enable = true,
            .focus_check_disable = false,
            .eoi_bcast_supp = false,
        };
    }

    _ = cores_online.fetchAdd(1, .release);
    arch.print("AP core {} online\n", .{apic.coreID()});
    arch.halt();
}

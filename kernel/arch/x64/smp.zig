const std = @import("std");
const zag = @import("zag");

const trampoline_code = @import("embedded_bins").trampoline;

const apic = zag.arch.x64.apic;
const arch = zag.arch.dispatch;
const cpu = zag.arch.x64.cpu;
const gdt = zag.arch.x64.gdt;
const idt = zag.arch.x64.idt;
const interrupts = zag.arch.x64.interrupts;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const pmm = zag.memory.pmm;
const sched = zag.sched.scheduler;
const stack_mod = zag.memory.stack;
const timers = zag.arch.x64.timers;

const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const TrampolineParams = extern struct {
    cr3: u64,
    stack_top: u64,
    entry_point: u64,
};

/// Trampoline must reside below 1 MiB — the SIPI vector encodes the page-aligned
/// start address as VV in 000VV000H.
/// Intel SDM Vol 3A, §11.4.4 "MP Initialization Example", step 10.
const TRAMPOLINE_PHYS: u64 = 0x8000;
const TRAMPOLINE_VECTOR: u8 = @intCast(TRAMPOLINE_PHYS >> 12);
const params_offset = trampoline_code.len - @sizeOf(TrampolineParams);

const KERNEL_PERMS = MemoryPerms{
    .write_perm = .write,
    .execute_perm = .no_execute,
    .cache_perm = .write_back,
    .global_perm = .global,
    .privilege_perm = .kernel,
};

var cores_online: std.atomic.Value(u32) = std.atomic.Value(u32).init(1);

/// Boots all application processors via the INIT-SIPI-SIPI sequence.
/// Intel SDM Vol 3A, §11.4.3 "MP Initialization Protocol Algorithm for MP Systems"
/// Intel SDM Vol 3A, §11.4.4 "MP Initialization Example", Table 11-1 — INIT-SIPI-SIPI
/// sequence with 10 ms delay between INIT and first SIPI.
pub fn smpInit() !void {
    for (0..apic.coreCount()) |i| {
        gdt.initForCore(i);
    }

    const trampoline_phys = PAddr.fromInt(TRAMPOLINE_PHYS);
    const trampoline_virt = VAddr.fromInt(TRAMPOLINE_PHYS);

    try arch.paging.mapPage(
        memory_init.kernel_addr_space_root,
        trampoline_phys,
        trampoline_virt,
        .{
            .write_perm = .write,
            .execute_perm = .execute,
            .cache_perm = .write_back,
            .global_perm = .not_global,
            .privilege_perm = .kernel,
        },
    );

    const dest: [*]u8 = @ptrFromInt(trampoline_virt.addr);
    @memcpy(dest[0..trampoline_code.len], trampoline_code);

    const params: *TrampolineParams = @ptrFromInt(trampoline_virt.addr + params_offset);
    params.cr3 = zag.arch.x64.paging.getAddrSpaceRoot().addr;
    params.entry_point = @intFromPtr(&coreInit);

    const bsp_id = apic.rawApicId();

    const pmm_iface = pmm.global_pmm.?.allocator();
    var hpet = &timers.hpet_timer;
    const hpet_iface = hpet.timer();

    for (apic.lapics.?) |la| {
        if (la.apic_id == bsp_id) {
            continue;
        }

        const ap_stack = try stack_mod.createKernel();

        var page_addr = ap_stack.base.addr;
        var map_ok = true;
        while (page_addr < ap_stack.top.addr) {
            const kpage = pmm_iface.create(paging.PageMem(.page4k)) catch {
                map_ok = false;
                break;
            };
            @memset(std.mem.asBytes(kpage), 0);
            const kphys = PAddr.fromVAddr(VAddr.fromInt(@intFromPtr(kpage)), null);
            arch.paging.mapPage(memory_init.kernel_addr_space_root, kphys, VAddr.fromInt(page_addr), KERNEL_PERMS) catch {
                pmm_iface.destroy(kpage);
                map_ok = false;
                break;
            };
            page_addr += paging.PAGE4K;
        }

        if (!map_ok) {
            stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
            continue;
        }

        params.stack_top = zag.memory.address.alignStack(ap_stack.top).addr;

        const expected = cores_online.load(.acquire);
        // Intel SDM Vol 3A, §11.4.4, Table 11-1: send INIT IPI, wait 10 ms,
        // then send SIPI. A second SIPI is not sent; we rely on the 100 ms
        // timeout to detect APs that fail to come online.
        apic.sendInitIpi(la.apic_id);

        const start = hpet_iface.now();
        while (hpet_iface.now() - start < 10_000_000) {
            std.atomic.spinLoopHint();
        }

        apic.sendSipi(la.apic_id, TRAMPOLINE_VECTOR);

        const timeout = hpet_iface.now();
        while (cores_online.load(.acquire) == expected) {
            if (hpet_iface.now() - timeout > 100_000_000) {
                stack_mod.destroyKernel(ap_stack, memory_init.kernel_addr_space_root);
                break;
            }
            std.atomic.spinLoopHint();
        }
    }
}

/// AP initialization entry point — corresponds to the "Typical AP Initialization Sequence"
/// in Intel SDM Vol 3A, §11.4.4.2.
fn coreInit() callconv(.c) noreturn {
    gdt.loadGdt(0);
    gdt.reloadSegments();
    cpu.lidt(&idt.idt_ptr);

    if (apic.x2_apic) {
        _ = cpu.enableX2Apic(@intFromEnum(interrupts.IntVecs.spurious));
    } else {
        apic.enableSpuriousVector(@intFromEnum(interrupts.IntVecs.spurious));
    }

    const core_id = apic.coreID();
    gdt.loadGdt(core_id);
    cpu.ltr(gdt.TSS_OFFSET);

    cpu.initSyscall(@intFromPtr(&interrupts.syscallEntry));
    interrupts.initSyscallScratch(core_id);
    cpu.initPat();
    cpu.enableSmapSmep();
    cpu.enablePcid();
    cpu.enableSpeculationBarriers();
    _ = cores_online.fetchAdd(1, .release);
    sched.perCoreInit();
    arch.cpu.halt();
}

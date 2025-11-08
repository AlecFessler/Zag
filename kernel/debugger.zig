const std = @import("std");
const zag = @import("zag");

const cpu = zag.x86.Cpu;
const interrupts = zag.x86.Interrupts;
const paging = zag.x86.Paging;
const panic_mod = zag.panic;
const pmm_mod = zag.memory.PhysicalMemoryManager;
const serial = zag.x86.Serial;
const sched = zag.sched.scheduler;

const PROCS_ARRAY_SIZE = 256;

pub fn dumpPageEntry(e: paging.PageEntry) void {
    serial.print("RW:{s} NX:{s} U:{s} C:{s} PAddr:0x{X}\n", .{
        @tagName(e.rw),
        @tagName(e.nx),
        @tagName(e.user),
        @tagName(e.cache_disable),
        e.getPAddr().addr,
    });
}

pub fn dumpPageEntryVerbose(e: paging.PageEntry) void {
    serial.print("   PAddr: 0x{X}\n", .{e.getPAddr().addr});
    serial.print("      RW: {s}\n", .{@tagName(e.rw)});
    serial.print("      NX: {s}\n", .{@tagName(e.nx)});
    serial.print("    User: {s}\n", .{@tagName(e.user)});
    serial.print("   Cache: {s}\n", .{@tagName(e.cache_disable)});
    serial.print("     WRT: {}\n", .{e.write_through});
    serial.print("    Huge: {}\n", .{e.huge_page});
    serial.print("  Global: {}\n", .{e.global});
    serial.print("Accessed: {}\n", .{e.accessed});
    serial.print("   Dirty: {}\n", .{e.dirty});
    serial.print("\n", .{});
}

pub fn dumpPageTables(pml4_virt: paging.VAddr) void {
    const l4_root: [*]paging.PageEntry = @ptrFromInt(pml4_virt.addr);
    const l3_page_entries = l4_root[0..paging.PAGE_TABLE_SIZE];
    for (l3_page_entries, 0..) |l3_e, l3_i| {
        if (!l3_e.present) continue;
        serial.print("[{}]: ", .{l3_i});
        dumpPageEntry(l3_e);
        //dumpPageEntryVerbose(l3_e);

        const l3_root_virt = paging.VAddr.fromPAddr(l3_e.getPAddr(), .physmap);
        const l3_root: [*]paging.PageEntry = @ptrFromInt(l3_root_virt.addr);
        const l2_page_entries = l3_root[0..paging.PAGE_TABLE_SIZE];
        for (l2_page_entries, 0..) |l2_e, l2_i| {
            if (!l2_e.present) continue;
            serial.print("[{},{}]: ", .{ l3_i, l2_i });
            dumpPageEntry(l2_e);
            //dumpPageEntryVerbose(l2_e);

            const l2_root_virt = paging.VAddr.fromPAddr(l2_e.getPAddr(), .physmap);
            const l2_root: [*]paging.PageEntry = @ptrFromInt(l2_root_virt.addr);
            const l1_page_entries = l2_root[0..paging.PAGE_TABLE_SIZE];
            for (l1_page_entries, 0..) |l1_e, l1_i| {
                if (!l1_e.present) continue;
                serial.print("[{},{},{}]: ", .{ l3_i, l2_i, l1_i });
                dumpPageEntry(l1_e);
                //dumpPageEntryVerbose(l1_e);
            }
        }
    }
}

pub fn dumpThreadVerbose(thread: *sched.Thread) void {
    serial.print("THREAD:\n", .{});
    serial.print("  TID: {}\n", .{thread.tid});
    serial.print("  PID: {}\n", .{thread.proc.pid});
    serial.print("  Kernel stack base: 0x{X}\n", .{thread.kstack_base.addr});
    if (thread.ustack_base) |ustack_base| {
        serial.print("  User stack base: 0x{X}\n", .{ustack_base.addr});
    }
    serial.print("\n", .{});
    interrupts.dumpInterruptFrame(thread.ctx);
    serial.print("\n", .{});
}

pub fn dumpThread(thread: *sched.Thread) void {
    serial.print("TID: {} PID: {}\n", .{ thread.tid, thread.proc.pid });
}

pub fn dumpProcessVerbose(proc: *sched.Process) void {
    serial.print("PROCESS:\n", .{});
    serial.print("  PID: {}\n", .{proc.pid});
    serial.print("  CPL: {s}\n", .{@tagName(proc.cpl)});
    serial.print("  PML4 VAddr: 0x{X}\n", .{proc.pml4_virt.addr});
    serial.print("  Num Threads: {}\n", .{proc.num_threads});
    serial.print("\n", .{});

    serial.print("  VMM Reserved Ranges:\n", .{});
    for (0..proc.vmm.vmm_allocations_idx) |i| {
        const region = proc.vmm.vmm_allocations[i];
        serial.print("    0x{X} - 0x{X}\n", .{
            region.vaddr.addr,
            region.vaddr.addr + region.size,
        });
    }
    serial.print("\n", .{});

    for (0..proc.num_threads) |i| {
        dumpThreadVerbose(proc.threads[i]);
    }
}

pub fn dumpProcess(proc: *sched.Process) void {
    serial.print("PID: {} CPL: {s}\n", .{ proc.pid, @tagName(proc.cpl) });
}

pub fn enumerateProcesses(procs_array: *[PROCS_ARRAY_SIZE]?*sched.Process) u64 {
    var current_thread: ?*sched.Thread = &sched.rq.sentinel;
    var max_pid: u64 = 0;
    while (current_thread) |thread| {
        if (procs_array[thread.proc.pid] == null) {
            procs_array[thread.proc.pid] = thread.proc;
            if (thread.proc.pid > max_pid) max_pid = thread.proc.pid;
        }
        current_thread = thread.next;
    }

    return max_pid;
}

pub fn init() void {
    const saved_rflags = cpu.saveAndDisableInterrupts();
    defer cpu.restoreInterrupts(saved_rflags);

    var procs_array: [PROCS_ARRAY_SIZE]?*sched.Process = .{null} ** PROCS_ARRAY_SIZE;
    const max_pid = enumerateProcesses(&procs_array);
    serial.print("\n", .{});
    for (0..max_pid + 1) |pid| {
        if (procs_array[pid]) |proc| {
            dumpProcess(proc);
        }
    }

    // NOTE: temporary while this runs as the entry point for a kernel thread during development
    cpu.halt();
}

const std = @import("std");
const zag = @import("zag");

const cpu = zag.x86.Cpu;
const exceptions = zag.x86.Exceptions;
const idt = zag.x86.Idt;
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

fn printStackUsage(stack_base: u64, rsp: u64, total_size_bytes: u64) void {
    if (total_size_bytes == 0) {
        serial.print("(unknown / 0 KiB)", .{});
        return;
    }

    const low = stack_base - total_size_bytes;

    if (!(rsp <= stack_base and rsp >= low)) {
        const total_kib = total_size_bytes / 1024;
        serial.print("(RSP out of stack / {d} KiB)", .{total_kib});
        return;
    }

    const used_bytes = stack_base - rsp;

    const used_kib_tenths: u64 = (used_bytes * 10) / 1024;
    const used_whole: u64 = used_kib_tenths / 10;
    const used_frac: u64 = used_kib_tenths % 10;

    const total_kib: u64 = total_size_bytes / 1024;

    serial.print("({d}.{d} KiB/{d} KiB)\n", .{ used_whole, used_frac, total_kib });
}

fn printRangeWithSize(lo: u64, hi: u64) void {
    if (hi <= lo) return;
    const bytes = hi - lo;

    const gib = bytes / (1024 * 1024 * 1024);
    const mib = (bytes / (1024 * 1024)) % 1024;
    const kib = (bytes / 1024) % 1024;

    serial.print("    · 0x{X:016} - 0x{X:016} (", .{ lo, hi });

    if (gib > 0) {
        serial.print("{d} GiB", .{gib});
        if (mib > 0 or kib > 0) serial.print(" {d} MiB {d} KiB", .{ mib, kib });
    } else if (mib > 0) {
        serial.print("{d} MiB", .{mib});
        if (kib > 0) serial.print(" {d} KiB", .{kib});
    } else {
        serial.print("{d} KiB", .{kib});
    }

    serial.print(")\n", .{});
}

pub fn printRflagsBrief(rfl: u64) void {
    var buf: [16]u8 = undefined;
    var i: usize = 0;

    if ((rfl & (1 << 9)) != 0) {
        buf[i] = 'I';
        i += 1;
        buf[i] = 'F';
        i += 1;
        buf[i] = ' ';
        i += 1;
    } // IF
    if ((rfl & (1 << 6)) != 0) {
        buf[i] = 'Z';
        i += 1;
        buf[i] = 'F';
        i += 1;
        buf[i] = ' ';
        i += 1;
    } // ZF
    if ((rfl & (1 << 2)) != 0) {
        buf[i] = 'P';
        i += 1;
        buf[i] = 'F';
        i += 1;
        buf[i] = ' ';
        i += 1;
    } // PF
    if ((rfl & (1 << 7)) != 0) {
        buf[i] = 'S';
        i += 1;
        buf[i] = 'F';
        i += 1;
        buf[i] = ' ';
        i += 1;
    } // SF

    if (i > 0 and buf[i - 1] == ' ') i -= 1;

    serial.print("    [{s}]", .{buf[0..i]});
}

pub fn dumpInterruptFrame(ctx: *cpu.Context) void {
    serial.print("🪂 INTERRUPT FRAME\n", .{});
    printRflagsBrief(ctx.rflags);
    const int_str = blk: {
        if (ctx.int_num <= 32) {
            const exception: exceptions.Exception = @enumFromInt(ctx.int_num);
            break :blk @tagName(exception);
        } else {
            const int_vec: idt.IntVectors = @enumFromInt(ctx.int_num);
            break :blk @tagName(int_vec);
        }
    };
    serial.print(" INT={s}\n", .{int_str});

    const words: [*]const u64 = @ptrCast(ctx);
    serial.print("    rfl=0x{X:016}  ", .{ctx.rflags});
    serial.print("rip=", .{});
    panic_mod.logAddr(ctx.rip);
    serial.print("    rsp=0x{X:016}   cs=0x{X:03}\n", .{ ctx.rsp, ctx.cs });
    serial.print("    err=0x{X:016}   ss=0x{X:03}\n", .{ ctx.ss, ctx.err_code });
    serial.print("\n", .{});

    const reg_names = [_][]const u8{
        "r15", "r14", "r13", "r12",
        "r11", "r10", " r9", " r8",
        "rdi", "rsi", "rbp", "rbx",
        "rdx", "rcx", "rax", "int",
    };

    var i: usize = 0;
    while (i < 16) : (i += 4) {
        serial.print(
            "    {s}=0x{X:016}  {s}=0x{X:016}  {s}=0x{X:016}  {s}=0x{X:016}\n",
            .{
                reg_names[i],     words[i],
                reg_names[i + 1], words[i + 1],
                reg_names[i + 2], words[i + 2],
                reg_names[i + 3], words[i + 3],
            },
        );
    }
}

pub fn dumpThreadVerbose(thread: *sched.Thread) void {
    serial.print("🧵 THREAD {}\n", .{thread.tid});
    serial.print("   🗂️ Kstack base: 0x{X:016} ", .{thread.kstack_base.addr});
    if (thread.ustack_base == null) {
        printStackUsage(thread.kstack_base.addr, thread.ctx.rsp, thread.kstack_pages * paging.PAGE4K);
    } else {
        printStackUsage(thread.kstack_base.addr, thread.kstack_base.addr, thread.kstack_pages * paging.PAGE4K);
        serial.print("   📚 Ustack base: 0x{X:016} ", .{thread.ustack_base.?.addr});
        printStackUsage(thread.ustack_base.?.addr, thread.ctx.rsp, thread.ustack_pages * paging.PAGE4K);
    }
    serial.print("\n", .{});
    dumpInterruptFrame(thread.ctx);
    serial.print("\n\n", .{});
}

pub fn dumpThread(thread: *sched.Thread) void {
    serial.print("TID: {} PID: {}\n", .{ thread.tid, thread.proc.pid });
}

pub fn dumpProcessVerbose(proc: *sched.Process) void {
    const ring_sym = if (proc.cpl == .ring_0) "👑" else "🔒";
    serial.print("{s} PROCESS {}\n", .{ ring_sym, proc.pid });
    serial.print("    PML4 @ 0x{X:016} | Threads: {}\n", .{ proc.pml4_virt.addr, proc.num_threads });

    serial.print("    VMM Reserved:\n", .{});
    for (0..proc.vmm.vmm_allocations_idx) |i| {
        const region = proc.vmm.vmm_allocations[i];
        printRangeWithSize(region.vaddr.addr, region.vaddr.addr + region.size);
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
            dumpProcessVerbose(proc);
        }
    }

    // NOTE: temporary while this runs as the entry point for a kernel thread during development
    cpu.halt();
}

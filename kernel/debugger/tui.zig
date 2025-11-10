//! Text UI printers for Zag debugger.
//!
//! Contains all pretty-printers and walkers used by the CLI. Stateless, reads
//! global process/thread index from `control` and uses helpers from `utils`.
//
//! # Directory
//!
//! ## Type Definitions
//! (none)
//
//! ## Constants
//! (none)
//
//! ## Variables
//! (none)
//
//! ## Functions
//! - `dumpInterruptFrame` – Pretty-print an interrupt context.
//! - `dumpPageEntry` – One-line page entry summary.
//! - `dumpPageEntryVerbose` – Multi-line page entry detail.
//! - `dumpPageTables` – Filtered page-table walk from a PML4.
//! - `dumpProcess` – Brief process header.
//! - `dumpProcessVerbose` – Full process (VMM ranges, threads).
//! - `dumpThread` – Brief thread header.
//! - `dumpThreadVerbose` – Full thread + registers.
//! - `printRflagsBrief` – Compact RFLAGS banner (IF/ZF/PF/SF).
//! - `help` – Print the debugger help and filter options.
//! - `lsProcs` – List processes (brief).
//! - `lsProcsVerbose` – List processes (verbose).
//! - `printIdx4` – Print `[l4,l3,l2,l1]` with gaps.
//! - `printRangeWithSize` – Print range with human-friendly size.
//! - `printStackUsage` – Print `(used/total)` for a stack.
//! - `printPageTables` – Print page tables for parsed `(pid, verbose, filter)`.
//! - `printProcess` – Print process for parsed `pid`.
//! - `printThread` – Print thread for parsed `tid`.

const std = @import("std");
const zag = @import("zag");

const cpu = zag.x86.Cpu;
const exceptions = zag.x86.Exceptions;
const idt = zag.x86.Idt;
const paging = zag.x86.Paging;
const panic_mod = zag.panic;
const sched = zag.sched.scheduler;
const serial = zag.x86.Serial;

const control = @import("control.zig");
const utils = @import("utils.zig");
const PageEntryFilter = utils.PageEntryFilter;
const matchesFilter = utils.matchesFilter;

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

    serial.print("    rfl=0x{X:016}  ", .{ctx.rflags});
    serial.print("rip=0x", .{});
    panic_mod.logAddr(ctx.rip);
    serial.print("    rsp=0x{X:016}   cs=0x{X:03}\n", .{ ctx.rsp, ctx.cs });
    serial.print("    err=0x{X:016}   ss=0x{X:03}\n", .{ ctx.err_code, ctx.ss });
    serial.print("\n", .{});

    const reg_names = [_][]const u8{
        "r15", "r14", "r13", "r12", "r11", "r10", " r9", " r8",
        "rdi", "rsi", "rbp", "rbx", "rdx", "rcx", "rax", "int",
    };
    const words: [*]const u64 = @ptrCast(ctx);

    var i: u64 = 0;
    while (i < 16) : (i += 4) {
        serial.print(
            "    {s}=0x{X:016}  {s}=0x{X:016}  {s}=0x{X:016}  {s}=0x{X:016}\n",
            .{ reg_names[i], words[i], reg_names[i + 1], words[i + 1], reg_names[i + 2], words[i + 2], reg_names[i + 3], words[i + 3] },
        );
    }
}

pub fn dumpPageEntry(e: paging.PageEntry) void {
    serial.print("RW:{s:>2} NX:{s:>2} U:{s:>2} C:{s:>6} PAddr:0x{X:016}\n", .{
        @tagName(e.rw), @tagName(e.nx), @tagName(e.user), @tagName(e.cache_disable), e.getPAddr().addr,
    });
}

pub fn dumpPageEntryVerbose(e: paging.PageEntry) void {
    serial.print("\n", .{});
    serial.print("    PAddr:    0x{X:016}\n", .{e.getPAddr().addr});
    serial.print("    RW:       {s}\n", .{@tagName(e.rw)});
    serial.print("    NX:       {s}\n", .{@tagName(e.nx)});
    serial.print("    User:     {s}\n", .{@tagName(e.user)});
    serial.print("    Cache:    {s}\n", .{@tagName(e.cache_disable)});
    serial.print("    WRT:      {}\n", .{e.write_through});
    serial.print("    Huge:     {}\n", .{e.huge_page});
    serial.print("    Global:   {}\n", .{e.global});
    serial.print("    Accessed: {}\n", .{e.accessed});
    serial.print("    Dirty:    {}\n", .{e.dirty});
    serial.print("\n", .{});
}

pub fn dumpPageTables(pml4_virt: paging.VAddr, verbose: bool, filter: ?PageEntryFilter) void {
    const L = paging.PAGE_TABLE_SIZE;
    const pml4: [*]paging.PageEntry = @ptrFromInt(pml4_virt.addr);

    var total_checked: u64 = 0;
    var total_matched: u64 = 0;

    for (pml4[0..L], 0..) |e4, idx4_us| {
        if (!e4.present) continue;
        const idx4: u64 = @intCast(idx4_us);

        const pdpt: [*]paging.PageEntry = @ptrFromInt(paging.VAddr.fromPAddr(e4.getPAddr(), .physmap).addr);
        for (pdpt[0..L], 0..) |e3, idx3_us| {
            if (!e3.present) continue;
            const idx3: u64 = @intCast(idx3_us);

            if (e3.huge_page) {
                total_checked += 1;
                if (matchesFilter(e3, filter, idx4, idx3, null, null, .page1g)) {
                    total_matched += 1;
                    printIdx4(idx4, idx3, null, null);
                    if (verbose) dumpPageEntryVerbose(e3) else dumpPageEntry(e3);
                }
                continue;
            }

            const pd: [*]paging.PageEntry = @ptrFromInt(paging.VAddr.fromPAddr(e3.getPAddr(), .physmap).addr);
            for (pd[0..L], 0..) |e2, idx2_us| {
                if (!e2.present) continue;
                const idx2: u64 = @intCast(idx2_us);

                if (e2.huge_page) {
                    total_checked += 1;
                    if (matchesFilter(e2, filter, idx4, idx3, idx2, null, .page2m)) {
                        total_matched += 1;
                        printIdx4(idx4, idx3, idx2, null);
                        if (verbose) dumpPageEntryVerbose(e2) else dumpPageEntry(e2);
                    }
                    continue;
                }

                const pt: [*]paging.PageEntry = @ptrFromInt(paging.VAddr.fromPAddr(e2.getPAddr(), .physmap).addr);
                for (pt[0..L], 0..) |e1, idx1_us| {
                    if (!e1.present) continue;
                    const idx1: u64 = @intCast(idx1_us);

                    total_checked += 1;
                    if (matchesFilter(e1, filter, idx4, idx3, idx2, idx1, .page4k)) {
                        total_matched += 1;
                        printIdx4(idx4, idx3, idx2, idx1);
                        if (verbose) dumpPageEntryVerbose(e1) else dumpPageEntry(e1);
                    }
                }
            }
        }
    }

    serial.print("{} matched filter / {} total\n", .{ total_matched, total_checked });
}

pub fn dumpProcess(proc: *sched.Process) void {
    const ring_sym = if (proc.cpl == .ring_0) "👑" else "🔒";
    serial.print("{s} PID: {}\n", .{ ring_sym, proc.pid });
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

    serial.print("    Threads:\n", .{});
    for (0..proc.num_threads) |i| {
        serial.print("     · ", .{});
        dumpThread(proc.threads[i]);
    }
}

pub fn dumpThread(thread: *sched.Thread) void {
    serial.print("TID {}", .{thread.tid});
    if (thread == sched.running_thread) serial.print(" (running 🚀)\n", .{}) else serial.print("\n", .{});
}

pub fn dumpThreadVerbose(thread: *sched.Thread) void {
    serial.print("🧵 THREAD {}", .{thread.tid});
    if (thread == sched.running_thread) serial.print(" (running 🚀)\n", .{}) else serial.print("\n", .{});

    serial.print("    🥞 Kstack base: 0x{X:016} ", .{thread.kstack_base.addr});
    if (thread.ustack_base == null) {
        if (thread == sched.running_thread) {
            const current_rsp = cpu.readCurrentRsp();
            printStackUsage(thread.kstack_base.addr, current_rsp, thread.kstack_pages * paging.PAGE4K);
        } else {
            printStackUsage(thread.kstack_base.addr, thread.ctx.rsp, thread.kstack_pages * paging.PAGE4K);
        }
    } else {
        printStackUsage(thread.kstack_base.addr, thread.kstack_base.addr, thread.kstack_pages * paging.PAGE4K);
        serial.print("    📚 Ustack base: 0x{X:016} ", .{thread.ustack_base.?.addr});
        printStackUsage(thread.ustack_base.?.addr, thread.ctx.rsp, thread.ustack_pages * paging.PAGE4K);
    }
    serial.print("\n", .{});

    dumpInterruptFrame(thread.ctx);
    serial.print("\n\n", .{});
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
    }
    if ((rfl & (1 << 6)) != 0) {
        buf[i] = 'Z';
        i += 1;
        buf[i] = 'F';
        i += 1;
        buf[i] = ' ';
        i += 1;
    }
    if ((rfl & (1 << 2)) != 0) {
        buf[i] = 'P';
        i += 1;
        buf[i] = 'F';
        i += 1;
        buf[i] = ' ';
        i += 1;
    }
    if ((rfl & (1 << 7)) != 0) {
        buf[i] = 'S';
        i += 1;
        buf[i] = 'F';
        i += 1;
        buf[i] = ' ';
        i += 1;
    }
    if (i > 0 and buf[i - 1] == ' ') i -= 1;

    serial.print("    [{s}]", .{buf[0..i]});
}

pub fn help() void {
    const cli = @import("cli.zig");
    serial.print("Commands:\n", .{});
    serial.print("  {s:<12} List processes\n", .{cli.Commands.lsprocs});
    serial.print("  {s:<12} List processes (verbose)\n", .{cli.Commands.lsprocsv});
    serial.print("  {s:<12} Show info for a process (usage: proc <pid>)\n", .{cli.Commands.proc});
    serial.print("  {s:<12} Show info for a thread (usage: thread <tid>)\n", .{cli.Commands.thread});
    serial.print("  {s:<12} Single-step a thread (usage: step <tid>)\n", .{cli.Commands.dbg_step});
    serial.print("  {s:<12} Dump page tables (usage: pt <pid> [filters])\n", .{cli.Commands.page_tables});
    serial.print("  {s:<12} Dump page tables (verbose) (usage: pt -v <pid> [filters])\n", .{cli.Commands.page_tablesv});
    serial.print("  {s:<12} Show this help menu\n", .{cli.Commands.help});
    serial.print("\n", .{});
    serial.print("Page table filter options:\n", .{});
    serial.print("  Flag:      Options:        Summary:\n", .{});
    serial.print("  ---------  --------------  -------------------------------\n", .{});
    serial.print("  -l4        <0-511>         Filter by L4 index\n", .{});
    serial.print("  -l3        <0-511>         Filter by L3 index\n", .{});
    serial.print("  -l2        <0-511>         Filter by L2 index\n", .{});
    serial.print("  -l1        <0-511>         Filter by L1 index\n", .{});
    serial.print("  -rw        <ro|rw>         Filter by read/write permission\n", .{});
    serial.print("  -nx        <x|nx>          Filter by execute permission\n", .{});
    serial.print("  -u         <u|su>          Filter by user/supervisor\n", .{});
    serial.print("  -cache     <cache|ncache>  Filter by cache setting\n", .{});
    serial.print("  -wrt       <true|false>    Filter by write-through\n", .{});
    serial.print("  -global    <true|false>    Filter by global flag\n", .{});
    serial.print("  -accessed  <true|false>    Filter by accessed bit\n", .{});
    serial.print("  -dirty     <true|false>    Filter by dirty bit\n", .{});
    serial.print("  -page4k    <true|false>    Filter 4KB pages\n", .{});
    serial.print("  -page2m    <true|false>    Filter 2MB pages\n", .{});
    serial.print("  -page1g    <true|false>    Filter 1GB pages\n", .{});
    serial.print("\nExample: pt 1 -rw rw -nx nx -page2m true\n", .{});
}

pub fn lsProcs() void {
    for (0..control.max_pid + 1) |pid| if (control.procs_array[pid]) |proc| dumpProcess(proc);
}

pub fn lsProcsVerbose() void {
    for (0..control.max_pid + 1) |pid| if (control.procs_array[pid]) |proc| dumpProcessVerbose(proc);
}

pub fn printIdx4(l4: ?u64, l3: ?u64, l2: ?u64, l1: ?u64) void {
    const idxs = [_]?u64{ l4, l3, l2, l1 };
    serial.print("[", .{});
    for (idxs, 0..) |maybe, n| {
        if (n != 0) serial.print(",", .{});
        if (maybe) |v| serial.print("{d:03}", .{v}) else serial.print("___", .{});
        if (n == idxs.len - 1) serial.print("]: ", .{});
    }
}

pub fn printRangeWithSize(lo: u64, hi: u64) void {
    if (hi <= lo) return;
    const bytes = hi - lo;
    const gib = bytes / (1024 * 1024 * 1024);
    const mib = (bytes / (1024 * 1024)) % 1024;
    const kib = (bytes / 1024) % 1024;

    serial.print("     · 0x{X:016} - 0x{X:016} (", .{ lo, hi });
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

pub fn printStackUsage(stack_base: u64, rsp: u64, total_size_bytes: u64) void {
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

pub fn printPageTables(pid: u64, verbose: bool, filter: ?PageEntryFilter) void {
    if (control.procs_array[pid]) |proc| {
        dumpPageTables(proc.pml4_virt, verbose, filter);
    } else {
        serial.print("Invalid pid: {}\n", .{pid});
    }
}

pub fn printProcess(pid: u64) void {
    if (control.procs_array[pid]) |proc| {
        dumpProcessVerbose(proc);
    } else {
        serial.print("Invalid pid: {}\n", .{pid});
    }
}

pub fn printThread(tid: u64) void {
    for (0..control.max_pid + 1) |pid| {
        if (control.procs_array[pid]) |proc| {
            for (0..proc.num_threads) |i| {
                const thread = proc.threads[i];
                if (thread.tid != tid) continue;
                dumpThreadVerbose(thread);
                return;
            }
        }
    }
    serial.print("Invalid tid: {}\n", .{tid});
}

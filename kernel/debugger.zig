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
const ps2 = zag.drivers.ps2_keyboard;
const keyboard = zag.hal.keyboard;

pub const PageEntryFilter = struct {
    l4: ?u9,
    l3: ?u9,
    l2: ?u9,
    l1: ?u9,
    rw: ?paging.RW,
    nx: ?paging.Executeable,
    u: ?paging.User,
    cache: ?paging.Cacheable,
    wrt: ?bool,
    global: ?bool,
    accessed: ?bool,
    dirty: ?bool,
    page4k: ?bool,
    page2m: ?bool,
    page1g: ?bool,
};

const PROCS_ARRAY_SIZE = 256;
const CMD_BUF_SIZE = 256;

var procs_array: [PROCS_ARRAY_SIZE]?*sched.Process = .{null} ** PROCS_ARRAY_SIZE;
var max_pid: u64 = 0;

pub fn dumpPageEntry(e: paging.PageEntry) void {
    serial.print("RW:{s:>2} NX:{s:>2} U:{s:>2} C:{s:>6} PAddr:0x{X:016}\n", .{
        @tagName(e.rw),
        @tagName(e.nx),
        @tagName(e.user),
        @tagName(e.cache_disable),
        e.getPAddr().addr,
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

fn printIdx4(l4: ?u64, l3: ?u64, l2: ?u64, l1: ?u64) void {
    const idxs = [_]?u64{ l4, l3, l2, l1 };

    serial.print("[", .{});
    for (idxs, 0..) |maybe, n| {
        if (n != 0) serial.print(",", .{});
        if (maybe) |v| {
            serial.print("{d:03}", .{v});
        } else {
            serial.print("___", .{});
        }
        if (n == idxs.len - 1) {
            serial.print("]: ", .{});
        }
    }
}

pub fn dumpPageTables(pml4_virt: paging.VAddr, verbose: bool) void {
    const L = paging.PAGE_TABLE_SIZE;
    const pml4: [*]paging.PageEntry = @ptrFromInt(pml4_virt.addr);

    for (pml4[0..L], 0..) |e4, idx4_us| {
        if (!e4.present) continue;
        const idx4: u64 = @intCast(idx4_us);
        const pdpt: [*]paging.PageEntry = @ptrFromInt(paging.VAddr.fromPAddr(e4.getPAddr(), .physmap).addr);

        for (pdpt[0..L], 0..) |e3, idx3_us| {
            if (!e3.present) continue;
            const idx3: u64 = @intCast(idx3_us);

            if (e3.huge_page) {
                printIdx4(idx4, idx3, null, null);
                if (verbose) dumpPageEntryVerbose(e3) else dumpPageEntry(e3);
                continue;
            }

            const pd: [*]paging.PageEntry = @ptrFromInt(paging.VAddr.fromPAddr(e3.getPAddr(), .physmap).addr);

            for (pd[0..L], 0..) |e2, idx2_us| {
                if (!e2.present) continue;
                const idx2: u64 = @intCast(idx2_us);

                if (e2.huge_page) {
                    printIdx4(idx4, idx3, idx2, null);
                    if (verbose) dumpPageEntryVerbose(e2) else dumpPageEntry(e2);
                    continue;
                }

                const pt: [*]paging.PageEntry = @ptrFromInt(paging.VAddr.fromPAddr(e2.getPAddr(), .physmap).addr);

                for (pt[0..L], 0..) |e1, idx1_us| {
                    if (!e1.present) continue;
                    const idx1: u64 = @intCast(idx1_us);

                    printIdx4(idx4, idx3, idx2, idx1);
                    if (verbose) dumpPageEntryVerbose(e1) else dumpPageEntry(e1);
                }
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

pub fn printRflagsBrief(rfl: u64) void {
    var buf: [16]u8 = undefined;
    var i: u64 = 0;

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

    serial.print("    rfl=0x{X:016}  ", .{ctx.rflags});
    serial.print("rip=0x", .{});
    panic_mod.logAddr(ctx.rip);
    serial.print("    rsp=0x{X:016}   cs=0x{X:03}\n", .{ ctx.rsp, ctx.cs });
    serial.print("    err=0x{X:016}   ss=0x{X:03}\n", .{ ctx.err_code, ctx.ss });
    serial.print("\n", .{});

    const reg_names = [_][]const u8{
        "r15", "r14", "r13", "r12",
        "r11", "r10", " r9", " r8",
        "rdi", "rsi", "rbp", "rbx",
        "rdx", "rcx", "rax", "int",
    };
    const words: [*]const u64 = @ptrCast(ctx);

    var i: u64 = 0;
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
    serial.print("🧵 THREAD {}", .{thread.tid});
    if (thread == sched.running_thread) {
        serial.print(" (running 🚀)\n", .{});
    } else {
        serial.print("\n", .{});
    }

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

pub fn dumpThread(thread: *sched.Thread) void {
    serial.print("TID {}", .{thread.tid});
    if (thread == sched.running_thread) {
        serial.print(" (running 🚀)\n", .{});
    } else {
        serial.print("\n", .{});
    }
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

pub fn dumpProcess(proc: *sched.Process) void {
    const ring_sym = if (proc.cpl == .ring_0) "👑" else "🔒";
    serial.print("{s} PID: {}\n", .{ ring_sym, proc.pid });
}

pub fn enumerateProcesses() void {
    var current_thread: ?*sched.Thread = &sched.rq.sentinel;
    while (current_thread) |thread| {
        if (procs_array[thread.proc.pid] == null) {
            procs_array[thread.proc.pid] = thread.proc;
            if (thread.proc.pid > max_pid) max_pid = thread.proc.pid;
        }
        current_thread = thread.next;
    }
}

pub fn lsProcs() void {
    for (0..max_pid + 1) |pid| {
        if (procs_array[pid]) |proc| {
            dumpProcess(proc);
        }
    }
}

pub fn lsProcsVerbose() void {
    for (0..max_pid + 1) |pid| {
        if (procs_array[pid]) |proc| {
            dumpProcessVerbose(proc);
        }
    }
}

pub fn printProcess(cmd: []const u8) void {
    const tail = cmd[Commands.proc.len..cmd.len];
    const pid = parseU64Dec(tail) orelse {
        serial.print("Invalid pid: {s}\n", .{tail});
        return;
    };
    if (procs_array[pid]) |proc| {
        dumpProcessVerbose(proc);
    } else {
        serial.print("Invalid pid: {}\n", .{pid});
    }
}

pub fn printThread(cmd: []const u8) void {
    const tail = cmd[Commands.thread.len..cmd.len];
    const tid = parseU64Dec(tail) orelse {
        serial.print("Invalid tid: {s}\n", .{tail});
        return;
    };

    for (0..max_pid + 1) |pid| {
        if (procs_array[pid]) |proc| {
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

pub fn printPageTables(cmd: []const u8, verbose: bool) void {
    const tail = if (verbose)
        cmd[Commands.page_tablesv.len..cmd.len]
    else
        cmd[Commands.page_tables.len..cmd.len];
    const pid = parseU64Dec(tail) orelse {
        serial.print("Invalid pid: {s}\n", .{tail});
        return;
    };
    if (procs_array[pid]) |proc| {
        dumpPageTables(proc.pml4_virt, verbose);
    } else {
        serial.print("Invalid pid: {}\n", .{pid});
    }
}

const Commands = struct {
    pub const lsprocs = "lsprocs";
    pub const lsprocsv = "lsprocs -v";
    pub const proc = "proc ";
    pub const thread = "thread ";
    pub const help = "help";
    pub const page_tables = "pt ";
    pub const page_tablesv = "pt -v ";
    pub const newline = "";
};

fn help() void {
    serial.print("Commands:\n", .{});
    serial.print("  {s:<12}  List processes\n", .{Commands.lsprocs});
    serial.print("  {s:<12}  List processes (verbose)\n", .{Commands.lsprocsv});
    serial.print("  {s:<12}  Show info for a process (usage: proc <pid>)\n", .{Commands.proc});
    serial.print("  {s:<12}  Show info for a thread (usage: thread <tid>)\n", .{Commands.thread});
    serial.print("  {s:<12}  Dump page tables (usage: pt <pid>)\n", .{Commands.page_tables});
    serial.print("  {s:<12}  Dump page tables (verbose) (usage: pt -v <pid>)\n", .{Commands.page_tablesv});
    serial.print("  {s:<12}  Show this help menu\n", .{Commands.help});
}

pub fn executeCmd(cmd: []const u8) void {
    if (std.mem.eql(u8, cmd, Commands.lsprocs)) {
        lsProcs();
    } else if (std.mem.eql(u8, cmd, Commands.lsprocsv)) {
        lsProcsVerbose();
    } else if (cmd.len > Commands.proc.len and std.mem.startsWith(u8, cmd, Commands.proc)) {
        printProcess(cmd);
    } else if (cmd.len > Commands.thread.len and std.mem.startsWith(u8, cmd, Commands.thread)) {
        printThread(cmd);
    } else if (cmd.len > Commands.page_tablesv.len and std.mem.startsWith(u8, cmd, Commands.page_tablesv)) {
        printPageTables(cmd, true);
        // page tables -v command must come before the non verbose command so it's parsed correctly
    } else if (cmd.len > Commands.page_tables.len and std.mem.startsWith(u8, cmd, Commands.page_tables)) {
        printPageTables(cmd, false);
    } else if (std.mem.eql(u8, cmd, Commands.help)) {
        help();
    } else if (std.mem.eql(u8, cmd, Commands.newline)) {
        return;
    } else {
        serial.print("Invalid Command: {s}\n", .{cmd});
    }
}

pub fn repl() void {
    var cmd_buf: [CMD_BUF_SIZE]u8 = undefined;
    var cmd_idx: u8 = 0;

    var exiting = false;
    while (!exiting) {
        if (ps2.pollKeyEvent()) |act| {
            if (act.action != .press) continue;

            switch (act.key) {
                .enter => {
                    serial.print("\n", .{});
                    const cmd_str = cmd_buf[0..cmd_idx];
                    executeCmd(cmd_str);
                    cmd_idx = 0;
                    continue;
                },
                .backspace => {
                    if (cmd_idx > 0) {
                        cmd_idx -= 1;
                        cmd_buf[cmd_idx] = 0;
                        serial.print("\x08 \x08", .{});
                    }
                    continue;
                },
                .escape => {
                    exiting = true;
                    continue;
                },
                else => {},
            }

            if (act.ascii) |a| {
                const ch: u8 = @intFromEnum(a);
                if (ch < 0x20 or ch == 0x7F) continue;
                if (cmd_idx >= CMD_BUF_SIZE) @panic("Debugger command buffer overflow");
                cmd_buf[cmd_idx] = ch;
                cmd_idx += 1;
                serial.print("{c}", .{ch});
            }
        }
    }
}

pub fn init() void {
    const saved_rflags = cpu.saveAndDisableInterrupts();

    enumerateProcesses();

    ps2.init(.{}) catch |e| {
        serial.print("ps/2 init failed: {}\n", .{e});
        cpu.restoreInterrupts(saved_rflags);
        cpu.halt();
    };

    repl();

    cpu.restoreInterrupts(saved_rflags);
    cpu.halt();
}

fn parseU64Dec(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var n: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        const d: u64 = c - '0';
        if (n > (@as(u64, ~@as(u64, 0)) - d) / 10) return null;
        n = n * 10 + d;
    }
    return n;
}

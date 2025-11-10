//! Debugger control and runtime glue for Zag.
//!
//! Owns process/thread indexing, stepping, and top-level init that jumps into
//! the CLI REPL. Keeps global state that the TUI reads.
//
//! # Directory
//! ## Type Definitions
//! (none)
//
//! ## Constants
//! - `PROCS_ARRAY_SIZE` – Maximum PIDs tracked in the in-memory index.
//
//! ## Variables
//! - `max_pid` – Highest PID discovered during enumeration.
//! - `procs_array` – Sparse PID→Process table.
//
//! ## Functions
//! - `enumerateProcesses` – Populate PID→Process table from run queue.
//! - `breakpoint` – Set a debug breakpoint.
//! - `setTF` – Set the trap flag.
//! - `debugStep` – Step a single instruction in a thread.
//! - `init` – Mask interrupts, enumerate, run REPL.

const std = @import("std");
const zag = @import("zag");
const cli = @import("cli.zig");
const tui = @import("tui.zig");
const utils = @import("utils.zig");

const cpu = zag.x86.Cpu;
const sched = zag.sched.scheduler;
const serial = zag.x86.Serial;

pub const PROCS_ARRAY_SIZE: usize = 256;

pub var max_pid: u64 = 0;
pub var procs_array: [PROCS_ARRAY_SIZE]?*sched.Process = .{null} ** PROCS_ARRAY_SIZE;

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

pub fn breakpoint() void {
    asm volatile ("int3");
}

fn setTF(ctx: *cpu.Context) void {
    ctx.rflags |= (@as(u64, 1) << 8);
}

pub fn debugStep(tid: u64) void {
    if (utils.threadFromTID(tid)) |target| {
        setTF(target.ctx);
        asm volatile (
            \\movq %[new_stack], %%rsp
            \\jmp commonInterruptStubEpilogue
            :
            : [new_stack] "r" (@intFromPtr(target.ctx)),
        );
    } else {
        serial.print("Invalid tid: {}\n", .{tid});
    }
}

pub fn init(ctx: *cpu.Context) void {
    const saved_rflags = cpu.saveAndDisableInterrupts();

    sched.running_thread.?.ctx = ctx;
    tui.dumpThreadVerbose(sched.running_thread.?);
    enumerateProcesses();
    cli.repl();

    cpu.restoreInterrupts(saved_rflags);
    cpu.halt();
}

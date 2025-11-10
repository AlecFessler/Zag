//! Debugger CLI and REPL for Zag.
//!
//! Parses commands, manages the input loop, and dispatches to TUI/controls.
//! Minimal dependencies: serial + PS/2 keyboard + helpers.
//
//! # Directory
//!
//! ## Type Definitions
//! - `Commands` – Static command strings for the REPL.
//!
//! ## Constants
//! - `CMD_BUF_SIZE` – Bytes in the REPL input buffer.
//
//! ## Variables
//! (none)
//
//! ## Functions
//! - `executeCmd` – Dispatch a command string.
//! - `parsePageEntryFilter` – Parse `pt` filter flags.
//! - `repl` – Read keys and run the REPL loop.
//! - `parsePrintPageTables` – Parse args then call TUI `printPageTables`.
//! - `parsePrintProcess` – Parse args then call TUI `printProcess`.
//! - `parsePrintThread` – Parse args then call TUI `printThread`.

const std = @import("std");
const zag = @import("zag");
const tui = @import("tui.zig");
const control = @import("control.zig");
const utils = @import("utils.zig");

const serial = zag.x86.Serial;
const ps2 = zag.drivers.ps2_keyboard;

pub const Commands = struct {
    pub const lsprocs = "lsprocs";
    pub const lsprocsv = "lsprocs -v";
    pub const proc = "proc ";
    pub const thread = "thread ";
    pub const help = "help";
    pub const page_tables = "pt ";
    pub const page_tablesv = "pt -v ";
    pub const dbg_step = "step ";
    pub const newline = "";
};

pub const CMD_BUF_SIZE: u64 = 256;

pub fn executeCmd(cmd: []const u8) void {
    if (std.mem.eql(u8, cmd, Commands.lsprocs)) {
        tui.lsProcs();
    } else if (std.mem.eql(u8, cmd, Commands.lsprocsv)) {
        tui.lsProcsVerbose();
    } else if (cmd.len > Commands.proc.len and std.mem.startsWith(u8, cmd, Commands.proc)) {
        parsePrintProcess(cmd);
    } else if (cmd.len > Commands.thread.len and std.mem.startsWith(u8, cmd, Commands.thread)) {
        parsePrintThread(cmd);
    } else if (cmd.len > Commands.page_tablesv.len and std.mem.startsWith(u8, cmd, Commands.page_tablesv)) {
        parsePrintPageTables(cmd, true);
    } else if (cmd.len > Commands.page_tables.len and std.mem.startsWith(u8, cmd, Commands.page_tables)) {
        parsePrintPageTables(cmd, false);
    } else if (cmd.len > Commands.dbg_step.len and std.mem.startsWith(u8, cmd, Commands.dbg_step)) {
        parseDebugStep(cmd);
    } else if (std.mem.eql(u8, cmd, Commands.help)) {
        tui.help();
    } else if (std.mem.eql(u8, cmd, Commands.newline)) {
        return;
    } else {
        serial.print("Invalid Command: {s}\n", .{cmd});
    }
}

fn parseDebugStep(cmd: []const u8) void {
    const tail = cmd[Commands.dbg_step.len..];
    const tid = utils.parseU64Dec(tail) orelse {
        serial.print("Invalid tid: {s}\n", .{tail});
        return;
    };
    control.debugStep(tid);
}

pub fn parsePageEntryFilter(args: []const u8) ?utils.PageEntryFilter {
    var filter = utils.PageEntryFilter{
        .l4 = null,
        .l3 = null,
        .l2 = null,
        .l1 = null,
        .rw = null,
        .nx = null,
        .u = null,
        .cache = null,
        .wrt = null,
        .global = null,
        .accessed = null,
        .dirty = null,
        .page4k = null,
        .page2m = null,
        .page1g = null,
    };

    var i: u64 = 0;
    while (i < args.len) {
        while (i < args.len and args[i] == ' ') : (i += 1) {}
        if (i >= args.len) break;
        if (args[i] != '-') {
            i += 1;
            continue;
        }

        const flag_start = i + 1;
        var flag_end = flag_start;
        while (flag_end < args.len and args[flag_end] != ' ') : (flag_end += 1) {}
        const flag = args[flag_start..flag_end];
        i = flag_end;

        while (i < args.len and args[i] == ' ') : (i += 1) {}
        if (i >= args.len) break;

        const val_start = i;
        var val_end = val_start;
        while (val_end < args.len and val_end < args.len and args[val_end] != ' ') : (val_end += 1) {}
        const val = args[val_start..val_end];
        i = val_end;

        if (std.mem.eql(u8, flag, "l4")) {
            if (utils.parseU64Dec(val)) |v| {
                if (v <= 511) filter.l4 = @intCast(v);
            }
        } else if (std.mem.eql(u8, flag, "l3")) {
            if (utils.parseU64Dec(val)) |v| {
                if (v <= 511) filter.l3 = @intCast(v);
            }
        } else if (std.mem.eql(u8, flag, "l2")) {
            if (utils.parseU64Dec(val)) |v| {
                if (v <= 511) filter.l2 = @intCast(v);
            }
        } else if (std.mem.eql(u8, flag, "l1")) {
            if (utils.parseU64Dec(val)) |v| {
                if (v <= 511) filter.l1 = @intCast(v);
            }
        } else if (std.mem.eql(u8, flag, "rw")) {
            if (std.mem.eql(u8, val, "ro")) {
                filter.rw = .ro;
            } else if (std.mem.eql(u8, val, "rw")) {
                filter.rw = .rw;
            }
        } else if (std.mem.eql(u8, flag, "nx")) {
            if (std.mem.eql(u8, val, "x")) {
                filter.nx = .x;
            } else if (std.mem.eql(u8, val, "nx")) {
                filter.nx = .nx;
            }
        } else if (std.mem.eql(u8, flag, "u")) {
            if (std.mem.eql(u8, val, "u")) {
                filter.u = .u;
            } else if (std.mem.eql(u8, val, "su")) {
                filter.u = .su;
            }
        } else if (std.mem.eql(u8, flag, "cache")) {
            if (std.mem.eql(u8, val, "cache")) {
                filter.cache = .cache;
            } else if (std.mem.eql(u8, val, "ncache")) {
                filter.cache = .ncache;
            }
        } else if (std.mem.eql(u8, flag, "wrt")) {
            if (std.mem.eql(u8, val, "true")) {
                filter.wrt = true;
            } else if (std.mem.eql(u8, val, "false")) {
                filter.wrt = false;
            }
        } else if (std.mem.eql(u8, flag, "global")) {
            if (std.mem.eql(u8, val, "true")) {
                filter.global = true;
            } else if (std.mem.eql(u8, val, "false")) {
                filter.global = false;
            }
        } else if (std.mem.eql(u8, flag, "accessed")) {
            if (std.mem.eql(u8, val, "true")) {
                filter.accessed = true;
            } else if (std.mem.eql(u8, val, "false")) {
                filter.accessed = false;
            }
        } else if (std.mem.eql(u8, flag, "dirty")) {
            if (std.mem.eql(u8, val, "true")) {
                filter.dirty = true;
            } else if (std.mem.eql(u8, val, "false")) {
                filter.dirty = false;
            }
        } else if (std.mem.eql(u8, flag, "page4k")) {
            if (std.mem.eql(u8, val, "true")) {
                filter.page4k = true;
            } else if (std.mem.eql(u8, val, "false")) {
                filter.page4k = false;
            }
        } else if (std.mem.eql(u8, flag, "page2m")) {
            if (std.mem.eql(u8, val, "true")) {
                filter.page2m = true;
            } else if (std.mem.eql(u8, val, "false")) {
                filter.page2m = false;
            }
        } else if (std.mem.eql(u8, flag, "page1g")) {
            if (std.mem.eql(u8, val, "true")) {
                filter.page1g = true;
            } else if (std.mem.eql(u8, val, "false")) {
                filter.page1g = false;
            }
        }
    }

    return filter;
}

fn parsePrintPageTables(cmd: []const u8, verbose: bool) void {
    var base_end = if (verbose) Commands.page_tablesv.len else Commands.page_tables.len;
    while (base_end < cmd.len and cmd[base_end] == ' ') : (base_end += 1) {}
    const pid_start = base_end;

    var pid_end = pid_start;
    while (pid_end < cmd.len and cmd[pid_end] != ' ') : (pid_end += 1) {}

    const pid_str = cmd[pid_start..pid_end];
    const pid = utils.parseU64Dec(pid_str) orelse {
        serial.print("Invalid pid: {s}\n", .{pid_str});
        return;
    };

    const filter_args = if (pid_end < cmd.len) cmd[pid_end..] else "";
    const filter = if (filter_args.len > 0) parsePageEntryFilter(filter_args) else null;
    tui.printPageTables(pid, verbose, filter);
}

fn parsePrintProcess(cmd: []const u8) void {
    const tail = cmd[Commands.proc.len..];
    const pid = utils.parseU64Dec(tail) orelse {
        serial.print("Invalid pid: {s}\n", .{tail});
        return;
    };
    tui.printProcess(pid);
}

fn parsePrintThread(cmd: []const u8) void {
    const tail = cmd[Commands.thread.len..];
    const tid = utils.parseU64Dec(tail) orelse {
        serial.print("Invalid tid: {s}\n", .{tail});
        return;
    };
    tui.printThread(tid);
}

pub fn repl() void {
    var cmd_buf: [CMD_BUF_SIZE]u8 = undefined;
    var cmd_idx: u8 = 0;

    serial.print("\nZag Dbg: ", .{});
    var exiting = false;
    while (!exiting) {
        if (ps2.pollKeyEvent()) |act| {
            if (act.action != .press) continue;

            switch (act.key) {
                .enter => {
                    serial.print("\nZag Dbg: ", .{});
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

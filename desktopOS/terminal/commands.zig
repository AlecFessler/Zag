const lib = @import("lib");
const render = @import("render.zig");

const channel = lib.channel;
const filesystem = lib.filesystem;
const perms = lib.perms;
const syscall = lib.syscall;

const embedded = @import("embedded_children");

const DATA_CHAN_SIZE: u64 = 4 * 4096;

pub var should_exit: bool = false;

// ── Filesystem state ────────────────────────────────────────────────
var fs_client: ?*filesystem.Client = null;
var cwd: [256]u8 = undefined;
var cwd_len: u8 = 1;

pub fn setFsClient(c: *filesystem.Client) void {
    fs_client = c;
    cwd[0] = '/';
    cwd_len = 1;
}

pub fn executeCommand(line: []const u8) void {
    var cmd_end: usize = 0;
    while (cmd_end < line.len and line[cmd_end] != ' ') {
        cmd_end += 1;
    }
    const cmd_name = line[0..cmd_end];

    var args_start = cmd_end;
    if (args_start < line.len and line[args_start] == ' ') {
        args_start += 1;
    }
    const args = line[args_start..];

    if (strEql(cmd_name, "clear")) {
        render.clearHistory();
    } else if (strEql(cmd_name, "exit")) {
        should_exit = true;
    } else if (strEql(cmd_name, "echo")) {
        runEcho(args);
    } else if (strEql(cmd_name, "cd")) {
        cmdCd(args);
    } else if (strEql(cmd_name, "ls")) {
        cmdLs(args);
    } else if (strEql(cmd_name, "mkdir")) {
        cmdSimple(args, .mkdir);
    } else if (strEql(cmd_name, "rmdir")) {
        cmdSimple(args, .rmdir);
    } else if (strEql(cmd_name, "mkfile")) {
        cmdSimple(args, .mkfile);
    } else if (strEql(cmd_name, "rmfile")) {
        cmdSimple(args, .rmfile);
    } else if (strEql(cmd_name, "cat")) {
        cmdCat(args);
    } else if (strEql(cmd_name, "write")) {
        cmdWrite(args);
    } else if (strEql(cmd_name, "pwd")) {
        render.appendHistory(cwd[0..cwd_len]);
        render.appendHistory("\n");
    } else if (cmd_name.len > 0) {
        render.appendHistory("unknown command: ");
        render.appendHistory(cmd_name);
        render.appendHistory("\n");
    }
}

// ── Filesystem commands ─────────────────────────────────────────────

const FsOp = enum { mkdir, rmdir, mkfile, rmfile };

fn cmdSimple(args: []const u8, op: FsOp) void {
    const client = fs_client orelse {
        render.appendHistory("error: no filesystem\n");
        return;
    };
    if (args.len == 0) {
        render.appendHistory("usage: ");
        render.appendHistory(switch (op) {
            .mkdir => "mkdir",
            .rmdir => "rmdir",
            .mkfile => "mkfile",
            .rmfile => "rmfile",
        });
        render.appendHistory(" <path>\n");
        return;
    }

    var path_buf: [512]u8 = undefined;
    const full = fullPath(args, &path_buf) orelse {
        render.appendHistory("error: path too long\n");
        return;
    };

    var resp_buf: [256]u8 = undefined;
    const result = switch (op) {
        .mkdir => client.mkdir(full, &resp_buf),
        .rmdir => client.rmdir(full, &resp_buf),
        .mkfile => client.mkfile(full, &resp_buf),
        .rmfile => client.rmfile(full, &resp_buf),
    };
    handleSimpleResponse(result);
}

fn cmdCd(args: []const u8) void {
    if (args.len == 0) {
        cwd[0] = '/';
        cwd_len = 1;
        return;
    }

    var path_buf: [512]u8 = undefined;
    const full = fullPath(args, &path_buf) orelse {
        render.appendHistory("error: path too long\n");
        return;
    };

    // Validate directory exists via ls
    const client = fs_client orelse {
        render.appendHistory("error: no filesystem\n");
        return;
    };
    var resp_buf: [4096]u8 = undefined;
    const result = client.ls(full, &resp_buf);
    if (result) |resp| {
        switch (resp) {
            .data => {
                // Directory exists — update cwd
                const len = @min(full.len, cwd.len);
                @memcpy(cwd[0..len], full[0..len]);
                cwd_len = @intCast(len);
                // Ensure trailing slash
                if (cwd_len > 1 and cwd[cwd_len - 1] != '/') {
                    if (cwd_len < cwd.len) {
                        cwd[cwd_len] = '/';
                        cwd_len += 1;
                    }
                }
            },
            .err => |msg| {
                render.appendHistory("cd: ");
                render.appendHistory(msg);
                render.appendHistory("\n");
            },
            .ok => {},
        }
    } else {
        render.appendHistory("cd: timeout\n");
    }
}

fn cmdLs(args: []const u8) void {
    const client = fs_client orelse {
        render.appendHistory("error: no filesystem\n");
        return;
    };

    var path_buf: [512]u8 = undefined;
    const path = if (args.len > 0)
        fullPath(args, &path_buf) orelse {
            render.appendHistory("error: path too long\n");
            return;
        }
    else
        cwd[0..cwd_len];

    var resp_buf: [4096]u8 = undefined;
    if (client.ls(path, &resp_buf)) |resp| {
        switch (resp) {
            .data => |data| {
                if (data.len > 0) {
                    render.appendHistory(data);
                }
            },
            .err => |msg| {
                render.appendHistory("ls: ");
                render.appendHistory(msg);
                render.appendHistory("\n");
            },
            .ok => {},
        }
    } else {
        render.appendHistory("ls: timeout\n");
    }
}

fn cmdCat(args: []const u8) void {
    const client = fs_client orelse {
        render.appendHistory("error: no filesystem\n");
        return;
    };
    if (args.len == 0) {
        render.appendHistory("usage: cat <path>\n");
        return;
    }

    var path_buf: [512]u8 = undefined;
    const full = fullPath(args, &path_buf) orelse {
        render.appendHistory("error: path too long\n");
        return;
    };

    var resp_buf: [4096]u8 = undefined;
    if (client.read(full, &resp_buf)) |resp| {
        switch (resp) {
            .data => |data| {
                if (data.len > 0) {
                    render.appendHistory(data);
                    render.appendHistory("\n");
                }
            },
            .err => |msg| {
                render.appendHistory("cat: ");
                render.appendHistory(msg);
                render.appendHistory("\n");
            },
            .ok => {},
        }
    } else {
        render.appendHistory("cat: timeout\n");
    }
}

fn cmdWrite(args: []const u8) void {
    const client = fs_client orelse {
        render.appendHistory("error: no filesystem\n");
        return;
    };

    // Parse: write <path> <content>
    var path_end: usize = 0;
    while (path_end < args.len and args[path_end] != ' ') {
        path_end += 1;
    }
    if (path_end == 0) {
        render.appendHistory("usage: write <path> <content>\n");
        return;
    }
    const path_arg = args[0..path_end];
    var content_start = path_end;
    if (content_start < args.len and args[content_start] == ' ') {
        content_start += 1;
    }
    const content = args[content_start..];

    var path_buf: [512]u8 = undefined;
    const full = fullPath(path_arg, &path_buf) orelse {
        render.appendHistory("error: path too long\n");
        return;
    };

    // Open, write, close
    var resp_buf: [256]u8 = undefined;
    if (client.open(full, &resp_buf)) |resp| {
        switch (resp) {
            .ok => {},
            .err => |msg| {
                render.appendHistory("write: open: ");
                render.appendHistory(msg);
                render.appendHistory("\n");
                return;
            },
            .data => {},
        }
    } else {
        render.appendHistory("write: open timeout\n");
        return;
    }

    if (content.len > 0) {
        if (client.fsWrite(content, &resp_buf)) |resp| {
            switch (resp) {
                .ok => {},
                .err => |msg| {
                    render.appendHistory("write: ");
                    render.appendHistory(msg);
                    render.appendHistory("\n");
                    _ = client.close(&resp_buf);
                    return;
                },
                .data => {},
            }
        } else {
            render.appendHistory("write: timeout\n");
            _ = client.close(&resp_buf);
            return;
        }
    }

    _ = client.close(&resp_buf);
    render.appendHistory("ok\n");
}

// ── Path helpers ────────────────────────────────────────────────────

fn fullPath(arg: []const u8, buf: []u8) ?[]const u8 {
    if (arg.len == 0) return null;

    if (arg[0] == '/') {
        // Absolute path
        if (arg.len > buf.len) return null;
        @memcpy(buf[0..arg.len], arg);
        return buf[0..arg.len];
    }

    // Relative path: prepend cwd
    const total = @as(usize, cwd_len) + arg.len;
    if (total > buf.len) return null;
    @memcpy(buf[0..cwd_len], cwd[0..cwd_len]);
    @memcpy(buf[cwd_len..][0..arg.len], arg);
    return buf[0..total];
}

fn handleSimpleResponse(result: ?filesystem.Client.Response) void {
    if (result) |resp| {
        switch (resp) {
            .ok => render.appendHistory("ok\n"),
            .err => |msg| {
                render.appendHistory("error: ");
                render.appendHistory(msg);
                render.appendHistory("\n");
            },
            .data => {},
        }
    } else {
        render.appendHistory("error: timeout\n");
    }
}

// ── Echo (existing zutil) ───────────────────────────────────────────

fn runEcho(args: []const u8) void {
    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true, .grant = true }).bits();
    const shm_handle = syscall.shm_create_with_rights(DATA_CHAN_SIZE, shm_rights) catch {
        render.appendHistory("error: failed to create channel\n");
        return;
    };

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, DATA_CHAN_SIZE, vm_rights) catch {
        render.appendHistory("error: failed to reserve vm\n");
        return;
    };
    syscall.shm_map(shm_handle, vm_result.handle, 0) catch {
        render.appendHistory("error: failed to map channel\n");
        return;
    };

    const region: [*]u8 = @ptrFromInt(vm_result.addr);
    const chan = channel.Channel.init(region[0..DATA_CHAN_SIZE], 0) orelse {
        render.appendHistory("error: failed to init channel\n");
        return;
    };

    const echo_elf = embedded.echo;
    const child_rights = (perms.ProcessRights{
        .grant_to_child = true,
        .mem_reserve = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(echo_elf.ptr), echo_elf.len, child_rights) catch {
        render.appendHistory("error: failed to spawn echo\n");
        return;
    };

    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
    }).bits();
    syscall.grant_perm(shm_handle, proc_handle, grant_rights) catch {
        render.appendHistory("error: grant_perm failed\n");
        return;
    };

    if (args.len > 0) {
        chan.sendMessage(.A, args) catch {
            render.appendHistory("error: sendMessage failed\n");
            return;
        };
    } else {
        chan.sendMessage(.A, "\n") catch {
            render.appendHistory("error: sendMessage failed\n");
            return;
        };
    }

    var recv_buf: [256]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 50000) : (attempts += 1) {
        if (chan.receiveMessage(.A, &recv_buf) catch null) |len| {
            render.appendHistory(recv_buf[0..len]);
            render.appendHistory("\n");
            return;
        }
        syscall.thread_yield();
    }
    render.appendHistory("error: echo timed out\n");
}

fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (ac != bc) return false;
    }
    return true;
}

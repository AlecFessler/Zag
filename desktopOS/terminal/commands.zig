const lib = @import("lib");
const render = @import("render.zig");

const channel = lib.channel;
const perms = lib.perms;
const syscall = lib.syscall;

const embedded = @import("embedded_children");

const DATA_CHAN_SIZE: u64 = 4 * 4096;

pub var should_exit: bool = false;

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
    } else if (cmd_name.len > 0) {
        render.appendHistory("unknown command: ");
        render.appendHistory(cmd_name);
        render.appendHistory("\n");
    }
}

fn runEcho(args: []const u8) void {
    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true, .grant = true }).bits();
    const shm_handle = syscall.shm_create_with_rights(DATA_CHAN_SIZE, shm_rights);
    if (shm_handle <= 0) {
        render.appendHistory("error: failed to create channel\n");
        return;
    }

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, DATA_CHAN_SIZE, vm_rights);
    if (vm_result.val < 0) {
        render.appendHistory("error: failed to reserve vm\n");
        return;
    }
    if (syscall.shm_map(@intCast(shm_handle), @intCast(vm_result.val), 0) != 0) {
        render.appendHistory("error: failed to map channel\n");
        return;
    }

    const region: [*]u8 = @ptrFromInt(vm_result.val2);
    const chan = channel.Channel.init(region[0..DATA_CHAN_SIZE]) orelse {
        render.appendHistory("error: failed to init channel\n");
        return;
    };

    const echo_elf = embedded.echo;
    const child_rights = (perms.ProcessRights{
        .grant_to = true,
        .mem_reserve = true,
    }).bits();
    const proc_handle = syscall.proc_create(@intFromPtr(echo_elf.ptr), echo_elf.len, child_rights);
    if (proc_handle <= 0) {
        render.appendHistory("error: failed to spawn echo\n");
        return;
    }

    const grant_rights = (perms.SharedMemoryRights{
        .read = true,
        .write = true,
    }).bits();
    const grant_result = syscall.grant_perm(@intCast(shm_handle), @intCast(proc_handle), grant_rights);
    if (grant_result != 0) {
        render.appendHistory("error: grant_perm failed\n");
        return;
    }

    if (args.len > 0) {
        chan.enqueue(.A, args) catch {
            render.appendHistory("error: enqueue failed\n");
            return;
        };
    } else {
        chan.enqueue(.A, "\n") catch {
            render.appendHistory("error: enqueue failed\n");
            return;
        };
    }

    var recv_buf: [256]u8 = undefined;
    var attempts: u32 = 0;
    while (attempts < 50000) : (attempts += 1) {
        if (chan.dequeue(.A, &recv_buf)) |len| {
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

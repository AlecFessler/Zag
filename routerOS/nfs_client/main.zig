const lib = @import("lib");

const nfs3 = @import("nfs3.zig");
const rpc = @import("rpc.zig");
const xdr = @import("xdr.zig");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

// ── UDP proxy message tags (must match router/udp_fwd.zig) ──────────

const MSG_UDP_SEND: u8 = 0x01;
const MSG_UDP_RECV: u8 = 0x02;
const MSG_UDP_BIND: u8 = 0x03;

// ── Configuration ───────────────────────────────────────────────────

const SERVER_IP = [4]u8{ 10, 0, 2, 1 };
const EXPORT_PATH = "/export/zagtest";
const MAX_PERMS = 128;
const MAX_PATH_COMPONENTS = 16;
const TIMEOUT_NS: u64 = 5_000_000_000; // 5 seconds
const MAX_RETRIES: u32 = 3;

// ── State machine ───────────────────────────────────────────────────

const State = enum {
    idle,
    mount_pending,
    mounted,
    lookup_pending,
    getattr_pending,
    read_pending,
    readdir_pending,
    create_pending,
    write_pending,
    mkdir_pending,
    remove_pending,
    rmdir_pending,
    rename_pending,
    commit_pending,
};

const RequestSource = enum { console, router };

// ── NFS Client state ────────────────────────────────────────────────

var router_chan: channel_mod.Channel = undefined;
var console_chan: ?channel_mod.Channel = null;
var has_router: bool = false;

var state: State = .idle;
var mounted: bool = false;
var root_fh: nfs3.FileHandle = .{};
var next_xid: u32 = 0;
var pending_xid: u32 = 0;
var request_source: RequestSource = .console;
var send_time_ns: u64 = 0;
var retry_count: u32 = 0;

// For multi-step operations
var current_fh: nfs3.FileHandle = .{};
var path_buf: [256]u8 = undefined;
var path_len: usize = 0;
var path_components: [MAX_PATH_COMPONENTS]struct { start: u16, len: u16 } = undefined;
var num_components: u32 = 0;
var lookup_depth: u32 = 0;
var read_offset: u64 = 0;
var readdir_cookie: u64 = 0;
var readdir_cookieverf: [8]u8 = [_]u8{0} ** 8;

// For write operations
var write_fh: nfs3.FileHandle = .{};
var write_offset: u64 = 0;
var awaiting_write_data: bool = false;

// For rename operations (need to resolve two paths)
var rename_from_fh: nfs3.FileHandle = .{};
var rename_from_name_buf: [256]u8 = undefined;
var rename_from_name_len: usize = 0;
var rename_dst_buf: [256]u8 = undefined;
var rename_dst_len: usize = 0;

// Retry state
var retry_buf: [2048]u8 = undefined;
var retry_len: usize = 0;

pub fn main(perm_view_addr: u64) void {
    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("nfs_client: no command channel\n");
        return;
    };

    // Request connection to router
    const router_entry = cmd.requestConnection(shm_protocol.ServiceId.ROUTER) orelse {
        syscall.write("nfs_client: no router connection allowed\n");
        return;
    };
    if (!cmd.waitForConnection(router_entry)) {
        syscall.write("nfs_client: router connection failed\n");
        return;
    }
    // Map the router data channel
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var data_shm_handle: u64 = 0;
    var data_shm_size: u64 = 0;
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
            e.field0 > shm_protocol.COMMAND_SHM_SIZE and
            e.handle != router_entry.shm_handle)
        {
            data_shm_handle = e.handle;
            data_shm_size = e.field0;
            break;
        }
    }
    // If we didn't find a separate one, use the entry's handle
    if (data_shm_handle == 0) {
        data_shm_handle = router_entry.shm_handle;
        data_shm_size = router_entry.shm_size;
    }

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, data_shm_size, vm_rights);
    if (vm_result.val < 0) {
        syscall.write("nfs_client: vm_reserve failed\n");
        return;
    }
    if (syscall.shm_map(data_shm_handle, @intCast(vm_result.val), 0) != 0) {
        syscall.write("nfs_client: shm_map failed\n");
        return;
    }
    const header: *channel_mod.ChannelHeader = @ptrFromInt(vm_result.val2);
    router_chan = channel_mod.Channel.openAsSideB(header) orelse {
        syscall.write("nfs_client: channel open failed\n");
        return;
    };
    has_router = true;

    // Identify ourselves to the router
    _ = router_chan.send(&[_]u8{@truncate(shm_protocol.ServiceId.NFS_CLIENT)});

    // Seed XID from clock to avoid NFS reply cache hits across reboots
    const seed_ns: u64 = @bitCast(syscall.clock_gettime());
    next_xid = @truncate(seed_ns);
    if (next_xid == 0) next_xid = 1;

    // Bind our UDP port via the router
    sendUdpBind(nfs3.LOCAL_PORT);

    // Auto-mount
    sendMountRequest();

    // Main loop
    while (true) {
        // Check for incoming UDP replies from router
        var router_buf: [2048]u8 = undefined;
        if (router_chan.recv(&router_buf)) |len| {
            handleRouterMessage(router_buf[0..len]);
        }

        // Detect console channel
        if (console_chan == null) {
            detectConsoleChannel(view);
        }

        // Check console commands
        if (console_chan) |*chan| {
            var cmd_buf: [256]u8 = undefined;
            if (chan.recv(&cmd_buf)) |len| {
                handleCommand(cmd_buf[0..len], .console);
            }
        }

        checkTimeout();
        syscall.thread_yield();
    }
}

fn detectConsoleChannel(view: *const [MAX_PERMS]pv.UserViewEntry) void {
    // Look for a new data SHM beyond the router's one
    var skip: u32 = 0;
    for (view) |*e| {
        if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
            e.field0 > shm_protocol.COMMAND_SHM_SIZE)
        {
            if (skip == 0) {
                skip += 1; // skip the router data SHM
                continue;
            }
            const vm_rights = (perms.VmReservationRights{
                .read = true,
                .write = true,
                .shareable = true,
            }).bits();
            const vm = syscall.vm_reserve(0, e.field0, vm_rights);
            if (vm.val >= 0) {
                if (syscall.shm_map(e.handle, @intCast(vm.val), 0) == 0) {
                    const hdr: *channel_mod.ChannelHeader = @ptrFromInt(vm.val2);
                    console_chan = channel_mod.Channel.openAsSideA(hdr) orelse continue;
                }
            }
            break;
        }
    }
}

// ── UDP send helpers ────────────────────────────────────────────────

fn sendUdpBind(port: u16) void {
    var msg: [3]u8 = undefined;
    msg[0] = MSG_UDP_BIND;
    msg[1] = @truncate(port >> 8);
    msg[2] = @truncate(port);
    _ = router_chan.send(&msg);
}

fn sendUdpPacket(dst_ip: [4]u8, dst_port: u16, src_port: u16, payload: []const u8) void {
    var msg: [2048]u8 = undefined;
    const total = 9 + payload.len;
    if (total > msg.len) return;
    msg[0] = MSG_UDP_SEND;
    @memcpy(msg[1..5], &dst_ip);
    msg[5] = @truncate(dst_port >> 8);
    msg[6] = @truncate(dst_port);
    msg[7] = @truncate(src_port >> 8);
    msg[8] = @truncate(src_port);
    @memcpy(msg[9..][0..payload.len], payload);
    _ = router_chan.send(msg[0..total]);

    // Save for retries
    if (total <= retry_buf.len) {
        @memcpy(retry_buf[0..total], msg[0..total]);
        retry_len = total;
    }
    send_time_ns = now();
    retry_count = 0;
}

fn now() u64 {
    return @bitCast(syscall.clock_gettime());
}

// ── Send NFS requests ───────────────────────────────────────────────

fn allocXid() u32 {
    const xid = next_xid;
    next_xid +%= 1;
    if (next_xid == 0) next_xid = 1;
    return xid;
}

fn sendMountRequest() void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildMountRequest(&buf, pending_xid, EXPORT_PATH);
    sendUdpPacket(SERVER_IP, nfs3.MOUNT_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .mount_pending;
}

fn sendLookup(dir_fh: *const nfs3.FileHandle, name: []const u8) void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildLookupRequest(&buf, pending_xid, dir_fh, name);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .lookup_pending;
}

fn sendRead(fh: *const nfs3.FileHandle, offset: u64) void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildReadRequest(&buf, pending_xid, fh, offset, nfs3.READ_SIZE);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .read_pending;
}

fn sendReadDir(dir_fh: *const nfs3.FileHandle) void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildReadDirRequest(&buf, pending_xid, dir_fh, readdir_cookie, readdir_cookieverf, 1024);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .readdir_pending;
}

fn sendCreate(dir_fh: *const nfs3.FileHandle, name: []const u8) void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildCreateRequest(&buf, pending_xid, dir_fh, name);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .create_pending;
}

fn sendWrite(fh: *const nfs3.FileHandle, offset: u64, data: []const u8) void {
    var buf: [2048]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildWriteRequest(&buf, pending_xid, fh, offset, data);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .write_pending;
}

fn sendMkdir(dir_fh: *const nfs3.FileHandle, name: []const u8) void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildMkdirRequest(&buf, pending_xid, dir_fh, name);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .mkdir_pending;
}

fn sendRemove(dir_fh: *const nfs3.FileHandle, name: []const u8) void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildRemoveRequest(&buf, pending_xid, dir_fh, name);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .remove_pending;
}

fn sendRmdir(dir_fh: *const nfs3.FileHandle, name: []const u8) void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildRmdirRequest(&buf, pending_xid, dir_fh, name);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .rmdir_pending;
}

fn sendRename(from_dir_fh: *const nfs3.FileHandle, from_name: []const u8, to_dir_fh: *const nfs3.FileHandle, to_name: []const u8) void {
    var buf: [1024]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildRenameRequest(&buf, pending_xid, from_dir_fh, from_name, to_dir_fh, to_name);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .rename_pending;
}

fn sendGetAttr(fh: *const nfs3.FileHandle) void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildGetAttrRequest(&buf, pending_xid, fh);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .getattr_pending;
}

fn sendCommit(fh: *const nfs3.FileHandle) void {
    var buf: [512]u8 = undefined;
    pending_xid = allocXid();
    const len = nfs3.buildCommitRequest(&buf, pending_xid, fh);
    sendUdpPacket(SERVER_IP, nfs3.NFS_PORT, nfs3.LOCAL_PORT, buf[0..len]);
    state = .commit_pending;
}

// ── Handle incoming router messages ─────────────────────────────────

fn handleRouterMessage(data: []const u8) void {
    if (data.len < 1) return;
    switch (data[0]) {
        MSG_UDP_RECV => handleUdpRecv(data),
        else => {},
    }
}

fn handleUdpRecv(data: []const u8) void {
    if (data.len < 9) return;
    const payload = data[9..];
    handleNfsReply(payload);
}

fn handleNfsReply(payload: []const u8) void {
    // Ignore packets with wrong XID (stale retransmissions from prior operations)
    if (state != .mounted and state != .idle) {
        if (!rpc.xidMatches(payload, pending_xid)) return;
    }
    switch (state) {
        .mount_pending => {
            if (nfs3.parseMountReply(payload, pending_xid)) |fh| {
                root_fh = fh;
                mounted = true;
                state = .mounted;
                sendResponse("NFS: mounted\n");
            } else {
                sendResponse("NFS: mount failed\n");
                state = .idle;
            }
        },
        .lookup_pending => {
            if (nfs3.parseLookupReply(payload, pending_xid)) |fh| {
                current_fh = fh;
                lookup_depth += 1;
                continueAfterLookup();
            } else {
                sendResponse("NFS: lookup failed\n");
                sendEof();
                state = .mounted;
            }
        },
        .read_pending => {
            if (nfs3.parseReadReply(payload, pending_xid)) |result| {
                sendDataToRequester(result.data);
                if (result.eof or result.data.len == 0) {
                    sendEof();
                    state = .mounted;
                } else {
                    read_offset += result.data.len;
                    sendRead(&current_fh, read_offset);
                }
            } else {
                sendResponse("NFS: read failed\n");
                sendEof();
                state = .mounted;
            }
        },
        .readdir_pending => {
            if (nfs3.parseReadDirReply(payload, pending_xid)) |result| {
                var resp_buf: [2048]u8 = undefined;
                var pos: usize = 0;
                var i: u32 = 0;
                while (i < result.count) : (i += 1) {
                    const entry = result.entries[i];
                    // Skip . and ..
                    if (entry.name.len == 1 and entry.name[0] == '.') continue;
                    if (entry.name.len == 2 and entry.name[0] == '.' and entry.name[1] == '.') continue;
                    const end = @min(pos + entry.name.len, resp_buf.len);
                    @memcpy(resp_buf[pos..end], entry.name[0..(end - pos)]);
                    pos = end;
                    if (pos < resp_buf.len) {
                        resp_buf[pos] = '\n';
                        pos += 1;
                    }
                }
                if (pos > 0) sendDataToRequester(resp_buf[0..pos]);
                if (result.eof) {
                    sendEof();
                    state = .mounted;
                } else {
                    readdir_cookie = result.entries[result.count - 1].cookie;
                    readdir_cookieverf = result.cookieverf;
                    sendReadDir(&current_fh);
                }
            } else {
                sendResponse("NFS: readdir failed\n");
                sendEof();
                state = .mounted;
            }
        },
        .create_pending => {
            if (nfs3.parseCreateReply(payload, pending_xid)) |fh| {
                if (pending_op == .touch_op) {
                    // touch: commit immediately, no write data prompt
                    write_fh = fh;
                    sendCommit(&write_fh);
                } else {
                    write_fh = fh;
                    write_offset = 0;
                    awaiting_write_data = true;
                    state = .mounted;
                    sendResponse("OK: send data\n");
                }
            } else {
                sendResponse("NFS: create failed\n");
                sendEof();
                state = .mounted;
            }
        },
        .write_pending => {
            if (nfs3.parseWriteReply(payload, pending_xid)) |bytes_written| {
                write_offset += bytes_written;
                awaiting_write_data = true;
                state = .mounted;
            } else {
                sendResponse("NFS: write failed\n");
                awaiting_write_data = false;
                state = .mounted;
            }
        },
        .mkdir_pending => {
            if (nfs3.parseMkdirReply(payload, pending_xid) != null) {
                sendResponse("OK\n");
            } else {
                sendResponse("NFS: mkdir failed\n");
            }
            sendEof();
            state = .mounted;
        },
        .remove_pending => {
            if (nfs3.parseRemoveReply(payload, pending_xid)) {
                sendResponse("OK\n");
            } else {
                sendResponse("NFS: remove failed\n");
            }
            sendEof();
            state = .mounted;
        },
        .rmdir_pending => {
            if (nfs3.parseRmdirReply(payload, pending_xid)) {
                sendResponse("OK\n");
            } else {
                sendResponse("NFS: rmdir failed\n");
            }
            sendEof();
            state = .mounted;
        },
        .rename_pending => {
            if (nfs3.parseRenameReply(payload, pending_xid)) {
                sendResponse("OK\n");
            } else {
                sendResponse("NFS: rename failed\n");
            }
            sendEof();
            state = .mounted;
        },
        .getattr_pending => {
            if (nfs3.parseGetAttrReply(payload, pending_xid)) |attr| {
                var resp_buf: [128]u8 = undefined;
                var pos: usize = 0;
                // File type
                const type_str: []const u8 = if (attr.ftype == nfs3.NF3REG) "file" else if (attr.ftype == nfs3.NF3DIR) "dir" else "other";
                @memcpy(resp_buf[pos..][0..5], "type=");
                pos += 5;
                @memcpy(resp_buf[pos..][0..type_str.len], type_str);
                pos += type_str.len;
                // Size
                @memcpy(resp_buf[pos..][0..6], " size=");
                pos += 6;
                var size_buf: [20]u8 = undefined;
                const size_str = formatSize(attr.size, &size_buf);
                @memcpy(resp_buf[pos..][0..size_str.len], size_str);
                pos += size_str.len;
                resp_buf[pos] = '\n';
                pos += 1;
                sendResponse(resp_buf[0..pos]);
            } else {
                sendResponse("NFS: stat failed\n");
            }
            sendEof();
            state = .mounted;
        },
        .commit_pending => {
            sendResponse("OK\n");
            sendEof();
            state = .mounted;
        },
        else => {},
    }
}

// ── Path resolution ─────────────────────────────────────────────────

fn parsePath(path: []const u8) void {
    // Copy path, split into components by '/'
    const copy_len = @min(path.len, path_buf.len);
    @memcpy(path_buf[0..copy_len], path[0..copy_len]);
    path_len = copy_len;
    num_components = 0;
    var start: u16 = 0;
    var i: u16 = 0;
    while (i < copy_len) : (i += 1) {
        if (path_buf[i] == '/') {
            if (i > start and num_components < MAX_PATH_COMPONENTS) {
                path_components[num_components] = .{ .start = start, .len = i - start };
                num_components += 1;
            }
            start = i + 1;
        }
    }
    if (i > start and num_components < MAX_PATH_COMPONENTS) {
        path_components[num_components] = .{ .start = start, .len = i - start };
        num_components += 1;
    }
}

fn getComponent(idx: u32) []const u8 {
    const comp = path_components[idx];
    return path_buf[comp.start..][0..comp.len];
}

fn continueAfterLookup() void {
    const target_depth: u32 = switch (pending_op) {
        .create, .mkdir_op, .remove, .rmdir_op, .rename_src, .rename_dst, .touch_op => if (num_components > 1) num_components - 1 else 0,
        .read, .readdir, .stat_op => num_components,
    };
    if (lookup_depth < target_depth) {
        sendLookup(&current_fh, getComponent(lookup_depth));
        return;
    }
    finishLookupChain();
}

// ── Command handling ────────────────────────────────────────────────

const CmdOp = enum { cat, ls, put, mkdir_cmd, rm, stat_cmd, mount_cmd };

fn handleCommand(data: []const u8, source: RequestSource) void {
    request_source = source;

    // Trim trailing newline
    var cmd = data;
    while (cmd.len > 0 and (cmd[cmd.len - 1] == '\n' or cmd[cmd.len - 1] == '\r')) {
        cmd = cmd[0 .. cmd.len - 1];
    }

    // Handle write data if awaiting
    if (awaiting_write_data) {
        if (cmd.len == 0) {
            // Empty line = EOF, commit
            awaiting_write_data = false;
            sendCommit(&write_fh);
            return;
        }
        // Send this data as a WRITE
        sendWrite(&write_fh, write_offset, cmd);
        awaiting_write_data = false;
        return;
    }

    if (!mounted and !startsWith(cmd, "mount")) {
        sendResponse("NFS: not mounted\n");
        sendEof();
        return;
    }

    if (state != .mounted and state != .idle) {
        sendResponse("NFS: busy\n");
        sendEof();
        return;
    }

    if (startsWith(cmd, "mount")) {
        sendMountRequest();
    } else if (startsWith(cmd, "ls")) {
        const path = trimCommand(cmd, "ls");
        startLookupChainForOp(path, .readdir);
    } else if (startsWith(cmd, "cat ")) {
        const path = trimCommand(cmd, "cat");
        startLookupChainForOp(path, .read);
    } else if (startsWith(cmd, "put ")) {
        const path = trimCommand(cmd, "put");
        startLookupChainForOp(path, .create);
    } else if (startsWith(cmd, "mkdir ")) {
        const path = trimCommand(cmd, "mkdir");
        startLookupChainForOp(path, .mkdir_op);
    } else if (startsWith(cmd, "rm ")) {
        const path = trimCommand(cmd, "rm");
        startLookupChainForOp(path, .remove);
    } else if (startsWith(cmd, "rmdir ")) {
        const path = trimCommand(cmd, "rmdir");
        startLookupChainForOp(path, .rmdir_op);
    } else if (startsWith(cmd, "mv ")) {
        handleMvCommand(cmd);
    } else if (startsWith(cmd, "touch ")) {
        const path = trimCommand(cmd, "touch");
        startLookupChainForOp(path, .touch_op);
    } else if (startsWith(cmd, "stat ")) {
        const path = trimCommand(cmd, "stat");
        startLookupChainForOp(path, .stat_op);
    } else if (startsWith(cmd, "status")) {
        if (mounted) {
            sendResponse("NFS: mounted\n");
        } else {
            sendResponse("NFS: not mounted\n");
        }
        sendEof();
    } else {
        sendResponse("NFS: unknown command\n");
        sendEof();
    }
}

// Operation tracking for lookup chains
var pending_op: enum { read, readdir, create, mkdir_op, remove, rmdir_op, rename_src, rename_dst, stat_op, touch_op } = .read;

fn startLookupChainForOp(path: []const u8, op: @TypeOf(pending_op)) void {
    pending_op = op;
    parsePath(path);
    lookup_depth = 0;
    current_fh = root_fh;

    const target_depth: u32 = switch (op) {
        .create, .mkdir_op, .remove, .rmdir_op, .rename_src, .rename_dst, .touch_op => if (num_components > 1) num_components - 1 else 0,
        .read, .readdir, .stat_op => num_components,
    };

    if (target_depth == 0) {
        finishLookupChain();
        return;
    }

    sendLookup(&current_fh, getComponent(0));
}

fn finishLookupChain() void {
    switch (pending_op) {
        .read => {
            read_offset = 0;
            sendRead(&current_fh, 0);
        },
        .readdir => {
            readdir_cookie = 0;
            readdir_cookieverf = [_]u8{0} ** 8;
            sendReadDir(&current_fh);
        },
        .create, .touch_op => {
            if (num_components > 0) {
                sendCreate(&current_fh, getComponent(num_components - 1));
            }
        },
        .mkdir_op => {
            if (num_components > 0) {
                sendMkdir(&current_fh, getComponent(num_components - 1));
            }
        },
        .remove => {
            if (num_components > 0) {
                sendRemove(&current_fh, getComponent(num_components - 1));
            }
        },
        .rmdir_op => {
            if (num_components > 0) {
                sendRmdir(&current_fh, getComponent(num_components - 1));
            }
        },
        .rename_src => {
            // Save the source parent FH and name, then resolve destination
            rename_from_fh = current_fh;
            if (num_components > 0) {
                const name = getComponent(num_components - 1);
                const copy_len = @min(name.len, rename_from_name_buf.len);
                @memcpy(rename_from_name_buf[0..copy_len], name[0..copy_len]);
                rename_from_name_len = copy_len;
            }
            // Now resolve destination path
            parsePath(rename_dst_buf[0..rename_dst_len]);
            lookup_depth = 0;
            current_fh = root_fh;
            pending_op = .rename_dst;

            const target_depth: u32 = if (num_components > 1) num_components - 1 else 0;
            if (target_depth == 0) {
                finishLookupChain();
                return;
            }
            sendLookup(&current_fh, getComponent(0));
        },
        .rename_dst => {
            // Both paths resolved, send RENAME
            if (num_components > 0) {
                const to_name = getComponent(num_components - 1);
                sendRename(&rename_from_fh, rename_from_name_buf[0..rename_from_name_len], &current_fh, to_name);
            }
        },
        .stat_op => {
            sendGetAttr(&current_fh);
        },
    }
}

fn startsWith(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    for (s[0..prefix.len], prefix) |a, b| {
        if (a != b) return false;
    }
    return true;
}

fn trimCommand(cmd: []const u8, prefix: []const u8) []const u8 {
    if (cmd.len <= prefix.len) return "/";
    var rest = cmd[prefix.len..];
    while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];
    if (rest.len == 0) return "/";
    return rest;
}

fn handleMvCommand(cmd: []const u8) void {
    // Parse "mv <src> <dst>"
    var rest = cmd;
    if (rest.len > 3) rest = rest[3..] else {
        sendResponse("usage: mv <src> <dst>\n");
        sendEof();
        return;
    }
    while (rest.len > 0 and rest[0] == ' ') rest = rest[1..];

    // Find space separating src and dst
    var split: usize = 0;
    while (split < rest.len and rest[split] != ' ') : (split += 1) {}
    if (split == 0 or split >= rest.len) {
        sendResponse("usage: mv <src> <dst>\n");
        sendEof();
        return;
    }
    const src = rest[0..split];
    var dst = rest[split..];
    while (dst.len > 0 and dst[0] == ' ') dst = dst[1..];
    if (dst.len == 0) {
        sendResponse("usage: mv <src> <dst>\n");
        sendEof();
        return;
    }

    // Save destination path for later
    const dst_copy_len = @min(dst.len, rename_dst_buf.len);
    @memcpy(rename_dst_buf[0..dst_copy_len], dst[0..dst_copy_len]);
    rename_dst_len = dst_copy_len;

    // Start resolving source path
    startLookupChainForOp(src, .rename_src);
}

fn formatSize(size: u64, buf: []u8) []const u8 {
    if (size == 0) {
        buf[0] = '0';
        return buf[0..1];
    }
    var v = size;
    var i: usize = buf.len;
    while (v > 0 and i > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @truncate(v % 10));
        v /= 10;
    }
    return buf[i..];
}

// ── Response helpers ────────────────────────────────────────────────

fn sendResponse(msg: []const u8) void {
    switch (request_source) {
        .console => {
            if (console_chan) |*chan| {
                _ = chan.send(msg);
            }
        },
        .router => {
            // TODO: FILE_DATA response to router
        },
    }
}

fn sendDataToRequester(data: []const u8) void {
    sendResponse(data);
}

fn sendEof() void {
    switch (request_source) {
        .console => {
            if (console_chan) |*chan| {
                _ = chan.send(&[_]u8{}); // 0-byte = EOF
            }
        },
        .router => {},
    }
}

// ── Timeout / retry ─────────────────────────────────────────────────

fn checkTimeout() void {
    if (state == .mounted or state == .idle) return;
    if (send_time_ns == 0) return;
    const elapsed = now() -| send_time_ns;
    if (elapsed < TIMEOUT_NS) return;

    retry_count += 1;
    if (retry_count > MAX_RETRIES) {
        syscall.write("nfs_client: timeout, giving up\n");
        sendResponse("NFS: timeout\n");
        sendEof();
        state = if (mounted) .mounted else .idle;
        return;
    }

    // Retry: resend the last UDP packet
    syscall.write("nfs_client: retrying...\n");
    if (retry_len > 0) {
        _ = router_chan.send(retry_buf[0..retry_len]);
        send_time_ns = now();
    }
}

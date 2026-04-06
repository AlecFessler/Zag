const lib = @import("lib");
const fs = @import("fs.zig");
const nvme = @import("nvme.zig");

const channel = lib.channel;
const filesystem = lib.filesystem;
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const Channel = channel.Channel;

const MAX_CLIENTS = 16;
const MAX_CONTROLLERS = 4;
const MAX_PERMS = 128;

var controllers: [MAX_CONTROLLERS]nvme.Controller = .{nvme.Controller{}} ** MAX_CONTROLLERS;
var ctrl_count: u8 = 0;
var clients: [MAX_CLIENTS]filesystem.Server = undefined;
var client_count: u8 = 0;

// ── Known SHM tracking ──────────────────────────────────────────────
var known_shm_handles: [32]u64 = .{0} ** 32;
var known_shm_count: u8 = 0;

fn pollNewShm(view_addr: u64) ?u64 {
    const view: *const [128]perm_view.UserViewEntry = @ptrFromInt(view_addr);
    for (view) |*entry| {
        if (entry.entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY) {
            var known = false;
            for (known_shm_handles[0..known_shm_count]) |h| {
                if (h == entry.handle) {
                    known = true;
                    break;
                }
            }
            if (!known and known_shm_count < 32) {
                known_shm_handles[known_shm_count] = entry.handle;
                known_shm_count += 1;
                return entry.handle;
            }
        }
    }
    return null;
}

pub fn main(perm_view_addr: u64) void {
    syscall.write("nvme_driver: starting\n");

    const view: *const [MAX_PERMS]perm_view.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Scan for NVMe devices: PCI class 0x01 (storage), subclass 0x08 (NVM)
    var nvme_handles: [MAX_CONTROLLERS]u64 = .{0} ** MAX_CONTROLLERS;
    var nvme_mmio_sizes: [MAX_CONTROLLERS]u32 = .{0} ** MAX_CONTROLLERS;
    var nvme_count: u8 = 0;

    for (view) |*entry| {
        if (entry.entry_type == perm_view.ENTRY_TYPE_EMPTY) continue;
        if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            if (entry.deviceClass() == @intFromEnum(perms.DeviceClass.storage) and
                entry.pciSubclass() == 0x08 and
                nvme_count < MAX_CONTROLLERS)
            {
                nvme_handles[nvme_count] = entry.handle;
                nvme_mmio_sizes[nvme_count] = entry.deviceSizeOrPortCount();
                nvme_count += 1;
            }
        }
    }

    if (nvme_count == 0) {
        syscall.write("nvme_driver: no NVMe controllers found\n");
        while (true) syscall.thread_yield();
    }

    for (nvme_handles[0..nvme_count], nvme_mmio_sizes[0..nvme_count]) |handle, mmio_size| {
        const err = controllers[ctrl_count].initFromHandle(handle, mmio_size);
        if (err == .none) {
            ctrl_count += 1;
        } else {
            syscall.write("nvme_driver: controller init failed\n");
        }
    }

    if (ctrl_count == 0) {
        syscall.write("nvme_driver: no controllers initialized\n");
        while (true) syscall.thread_yield();
    }

    // Initialize filesystem on first controller
    if (!fs.init(&controllers[0])) {
        syscall.write("nvme_driver: filesystem init failed\n");
        while (true) syscall.thread_yield();
    }
    syscall.write("nvme_driver: filesystem ready\n");

    // Broadcast filesystem service
    channel.broadcast(@intFromEnum(filesystem.protocol_id)) catch {
        syscall.write("nvme_driver: FAIL broadcast\n");
        while (true) syscall.thread_yield();
    };
    syscall.write("nvme_driver: broadcast ok\n");

    // Main loop: accept clients and serve filesystem requests
    var req_buf: [4096]u8 = undefined;
    while (true) {
        // Accept new filesystem clients
        if (pollNewShm(perm_view_addr)) |shm_handle| {
            if (Channel.connectAsB(shm_handle, filesystem.SHM_SIZE) catch null) |chan| {
                if (client_count < MAX_CLIENTS) {
                    clients[client_count] = filesystem.Server.init(chan);
                    client_count += 1;
                    syscall.write("nvme_driver: fs client connected\n");
                }
            }
        }

        // Poll all clients for requests
        var had_work = false;
        for (clients[0..client_count]) |*client| {
            if (client.recv(&req_buf)) |req| {
                had_work = true;
                handleRequest(client, req);
            }
        }

        if (!had_work) {
            syscall.thread_yield();
        }
    }
}

fn handleRequest(server: *const filesystem.Server, req: filesystem.Server.Request) void {
    switch (req.tag) {
        0x01 => { // mkdir
            if (fs.mkdir(req.payload)) {
                server.sendOk();
            } else {
                server.sendError("mkdir failed");
            }
        },
        0x02 => { // rmdir
            if (fs.rmdir(req.payload)) {
                server.sendOk();
            } else {
                server.sendError("rmdir failed");
            }
        },
        0x03 => { // mkfile
            if (fs.mkfile(req.payload)) {
                server.sendOk();
            } else {
                server.sendError("mkfile failed");
            }
        },
        0x04 => { // rmfile
            if (fs.rmfile(req.payload)) {
                server.sendOk();
            } else {
                server.sendError("rmfile failed");
            }
        },
        0x05 => { // read: offset(u64) + size(u64) + path
            if (req.payload.len < 16) {
                server.sendError("read: bad payload");
                return;
            }
            const offset = readU64(req.payload, 0);
            const size = readU64(req.payload, 8);
            const path = req.payload[16..];
            var out_buf: [4096]u8 = undefined;
            const len = fs.readFile(path, offset, size, &out_buf);
            server.sendData(out_buf[0..len]);
        },
        0x06 => { // write: offset(u64) + path_len(u16) + path + data
            if (req.payload.len < 10) {
                server.sendError("write: bad payload");
                return;
            }
            const offset = readU64(req.payload, 0);
            const path_len: u16 = @as(u16, req.payload[8]) | (@as(u16, req.payload[9]) << 8);
            if (req.payload.len < 10 + path_len) {
                server.sendError("write: bad path");
                return;
            }
            const path = req.payload[10..][0..path_len];
            const data = req.payload[10 + path_len ..];
            if (fs.writeFile(path, offset, data)) {
                server.sendOk();
            } else {
                server.sendError("write failed");
            }
        },
        0x07 => { // ls
            var out_buf: [4096]u8 = undefined;
            const len = fs.ls(req.payload, &out_buf);
            if (len > 0) {
                server.sendData(out_buf[0..len]);
            } else {
                server.sendData(&[0]u8{});
            }
        },
        0x08 => { // stat
            if (fs.stat(req.payload)) |result| {
                server.sendStat(.{
                    .size = result.size,
                    .file_type = if (result.inode_type == 1) .file else .directory,
                    .created = 0,
                    .modified = 0,
                    .accessed = 0,
                });
            } else {
                server.sendError("stat failed");
            }
        },
        0x09 => { // rename: path1_len(u16) + path1 + path2
            if (req.payload.len < 2) {
                server.sendError("rename: bad payload");
                return;
            }
            const path1_len: u16 = @as(u16, req.payload[0]) | (@as(u16, req.payload[1]) << 8);
            if (req.payload.len < 2 + path1_len) {
                server.sendError("rename: bad path");
                return;
            }
            const path1 = req.payload[2..][0..path1_len];
            const path2 = req.payload[2 + path1_len ..];
            if (fs.renamePath(path1, path2)) {
                server.sendOk();
            } else {
                server.sendError("rename failed");
            }
        },
        0x0A => { // truncate: size(u64) + path
            if (req.payload.len < 8) {
                server.sendError("truncate: bad payload");
                return;
            }
            const size = readU64(req.payload, 0);
            const path = req.payload[8..];
            if (fs.truncateFile(path, size)) {
                server.sendOk();
            } else {
                server.sendError("truncate failed");
            }
        },
        else => {
            server.sendError("unknown command");
        },
    }
}

fn readU64(buf: []const u8, offset: usize) u64 {
    return @as(u64, buf[offset]) |
        (@as(u64, buf[offset + 1]) << 8) |
        (@as(u64, buf[offset + 2]) << 16) |
        (@as(u64, buf[offset + 3]) << 24) |
        (@as(u64, buf[offset + 4]) << 32) |
        (@as(u64, buf[offset + 5]) << 40) |
        (@as(u64, buf[offset + 6]) << 48) |
        (@as(u64, buf[offset + 7]) << 56);
}

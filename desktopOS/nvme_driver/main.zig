const lib = @import("lib");
const fs = @import("fs.zig");
const nvme = @import("nvme.zig");

const channel = lib.channel;
const filesystem = lib.filesystem;
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const MAX_CLIENTS = 16;
const MAX_CONTROLLERS = 4;
const MAX_PERMS = 128;

var controllers: [MAX_CONTROLLERS]nvme.Controller = .{nvme.Controller{}} ** MAX_CONTROLLERS;
var ctrl_count: u8 = 0;
var clients: [MAX_CLIENTS]filesystem.Server = undefined;
var client_count: u8 = 0;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("nvme_driver: starting\n");

    const view: *const [MAX_PERMS]perm_view.UserViewEntry = @ptrFromInt(channel.perm_view_addr);

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

    // Make filesystem discoverable
    channel.makeDiscoverable(@enumFromInt(@intFromEnum(filesystem.protocol_id)), 2) catch {
        syscall.write("nvme_driver: FAIL makeDiscoverable\n");
        while (true) syscall.thread_yield();
    };
    syscall.write("nvme_driver: discoverable\n");

    // Main loop: accept clients and serve filesystem requests
    var req_buf: [4096]u8 = undefined;
    while (true) {
        // Accept new filesystem clients
        if (channel.pollAnyIncoming()) |chan| {
            if (client_count < MAX_CLIENTS) {
                clients[client_count] = filesystem.Server.init(chan);
                client_count += 1;
                syscall.write("nvme_driver: fs client connected\n");
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
        0x05 => { // open
            if (fs.openFile(req.payload)) {
                server.sendOk();
            } else {
                server.sendError("open failed");
            }
        },
        0x06 => { // write
            if (fs.writeFile(req.payload)) {
                server.sendOk();
            } else {
                server.sendError("write failed");
            }
        },
        0x07 => { // close
            fs.closeFile();
            server.sendOk();
        },
        0x08 => { // ls
            var out_buf: [4096]u8 = undefined;
            const len = fs.ls(req.payload, &out_buf);
            if (len > 0) {
                server.sendData(out_buf[0..len]);
            } else {
                server.sendData(&[0]u8{});
            }
        },
        0x09 => { // read
            var out_buf: [4096]u8 = undefined;
            const len = fs.readFile(req.payload, &out_buf);
            server.sendData(out_buf[0..len]);
        },
        else => {
            server.sendError("unknown command");
        },
    }
}

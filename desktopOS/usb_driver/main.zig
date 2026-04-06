const lib = @import("lib");
const kb = @import("keyboard.zig");
const ms = @import("mouse.zig");
const xhci = @import("xhci.zig");

const channel = lib.channel;
const keyboard = lib.keyboard;
const mouse = lib.mouse;
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const Channel = channel.Channel;

const MAX_KB_CHANNELS = 16;
const MAX_MOUSE_CHANNELS = 4;
const MAX_PERMS = 128;
const MAX_USB_CONTROLLERS = 8;
const DEFAULT_SHM_SIZE: u64 = 4 * syscall.PAGE4K;

var kb_servers: [MAX_KB_CHANNELS]keyboard.Server = undefined;
var kb_count: u8 = 0;
var mouse_servers: [MAX_MOUSE_CHANNELS]mouse.Server = undefined;
var mouse_count: u8 = 0;
var controllers: [MAX_USB_CONTROLLERS]xhci.Controller = .{xhci.Controller{}} ** MAX_USB_CONTROLLERS;
var ctrl_count: u8 = 0;

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
    channel.broadcast(@intFromEnum(keyboard.protocol_id)) catch return;
    channel.broadcast(@intFromEnum(mouse.protocol_id)) catch return;

    // Collect all USB device handles from permission view
    const view: *const [MAX_PERMS]perm_view.UserViewEntry = @ptrFromInt(perm_view_addr);
    var usb_handles: [MAX_USB_CONTROLLERS]u64 = .{0} ** MAX_USB_CONTROLLERS;
    var usb_mmio_sizes: [MAX_USB_CONTROLLERS]u32 = .{0} ** MAX_USB_CONTROLLERS;
    var usb_count: u8 = 0;

    for (view) |*entry| {
        if (entry.entry_type == perm_view.ENTRY_TYPE_EMPTY) continue;
        if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            if (entry.deviceClass() == @intFromEnum(perms.DeviceClass.usb) and
                usb_count < MAX_USB_CONTROLLERS)
            {
                usb_handles[usb_count] = entry.handle;
                usb_mmio_sizes[usb_count] = entry.deviceSizeOrPortCount();
                usb_count += 1;
            }
        }
    }

    if (usb_count == 0) while (true) syscall.thread_yield();

    // Initialize all USB controllers
    for (usb_handles[0..usb_count], usb_mmio_sizes[0..usb_count]) |handle, mmio_size| {
        const err = controllers[ctrl_count].initFromHandle(handle, mmio_size);
        if (err == .none) {
            ctrl_count += 1;
        }
    }

    // Main event loop
    while (true) {
        // Accept new channels from clients
        if (pollNewShm(perm_view_addr)) |shm_handle| {
            if (Channel.connectAsB(shm_handle, DEFAULT_SHM_SIZE) catch null) |chan| {
                switch (@as(lib.Protocol, @enumFromInt(chan.protocol_id))) {
                    .keyboard => {
                        if (kb_count < MAX_KB_CHANNELS) {
                            kb_servers[kb_count] = keyboard.Server.init(chan);
                            kb_count += 1;
                        }
                    },
                    .mouse => {
                        if (mouse_count < MAX_MOUSE_CHANNELS) {
                            mouse_servers[mouse_count] = mouse.Server.init(chan);
                            mouse_count += 1;
                        }
                    },
                    else => {},
                }
            }
        }

        // Poll all controllers for events
        var had_event = false;
        for (controllers[0..ctrl_count]) |*ctrl| {
            if (ctrl.pollEvent()) |evt| {
                had_event = true;
                if (evt.trbType() == .transfer_event) {
                    const cc = evt.completionCode();
                    const slot_id = evt.slotId();
                    const ep_id = evt.endpointId();
                    if (cc == .success or cc == .short_packet) {
                        for (ctrl.hidDevices()) |*dev| {
                            if (dev.slot_id == slot_id and dev.ep_dci == ep_id and dev.active) {
                                const report = ctrl.getReportData(dev.buf_index);

                                switch (dev.protocol) {
                                    .keyboard => {
                                        kb.processReport(dev, report, kb_servers[0..kb_count]);
                                    },
                                    .mouse => {
                                        ms.processReport(report, &dev.report_info, mouse_servers[0..mouse_count]);
                                    },
                                }

                                ctrl.queueInterruptIn(slot_id, dev.ep_dci, dev.buf_index);
                                ctrl.ringDoorbell(slot_id, dev.ep_dci);
                                break;
                            }
                        }
                    }
                }
                ctrl.advanceEventRing();
            }
        }

        if (!had_event) {
            syscall.thread_yield();
        }
    }
}

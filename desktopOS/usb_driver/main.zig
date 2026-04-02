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
const MAX_PERMS = 128;
const MAX_USB_CONTROLLERS = 8;
const DEFAULT_SHM_SIZE: u64 = 4 * syscall.PAGE4K;

var kb_channels: [MAX_KB_CHANNELS]*Channel = undefined;
var kb_count: u8 = 0;
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
    syscall.write("usb_driver: starting\n");

    // Broadcast keyboard service
    channel.broadcast(@intFromEnum(keyboard.protocol_id)) catch {
        syscall.write("usb_driver: FAIL broadcast keyboard\n");
        return;
    };

    // Connect to compositor for mouse events
    var mouse_client_opt: ?mouse.Client = null;
    while (mouse_client_opt == null) {
        mouse_client_opt = mouse.connectToMouseServer(perm_view_addr) catch |err| switch (err) {
            error.ServerNotFound => null,
            error.ChannelFailed => {
                syscall.write("usb_driver: FAIL connect mouse\n");
                return;
            },
        };
        if (mouse_client_opt == null) syscall.thread_yield();
    }
    const mouse_client = mouse_client_opt.?;
    syscall.write("usb_driver: mouse channel connected to compositor\n");

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

    if (usb_count == 0) {
        syscall.write("usb_driver: no USB controllers\n");
        while (true) syscall.thread_yield();
    }

    // Initialize all USB controllers
    for (usb_handles[0..usb_count], usb_mmio_sizes[0..usb_count]) |handle, mmio_size| {
        const err = controllers[ctrl_count].initFromHandle(handle, mmio_size);
        if (err == .none) {
            ctrl_count += 1;
        }
    }

    // Main event loop
    while (true) {
        // Accept new keyboard channels from terminals
        if (pollNewShm(perm_view_addr)) |shm_handle| {
            if (Channel.connectAsB(shm_handle, DEFAULT_SHM_SIZE)) |chan| {
                if (kb_count < MAX_KB_CHANNELS) {
                    kb_channels[kb_count] = chan;
                    kb_count += 1;
                    syscall.write("usb_driver: keyboard channel connected\n");
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
                                        // Send to all connected keyboard channels
                                        kb.processReport(dev, report, kb_channels[0..kb_count]);
                                    },
                                    .mouse => {
                                        ms.processReport(report, &dev.report_info, &mouse_client);
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

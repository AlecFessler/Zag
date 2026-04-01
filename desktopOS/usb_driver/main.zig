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

const MAX_KB_CHANNELS = 16;
const MAX_PERMS = 128;
const MAX_USB_CONTROLLERS = 8;

var kb_channels: [MAX_KB_CHANNELS]*channel.Channel = undefined;
var kb_count: u8 = 0;
var active_semantic_id: u64 = 0;
var controllers: [MAX_USB_CONTROLLERS]xhci.Controller = .{xhci.Controller{}} ** MAX_USB_CONTROLLERS;
var ctrl_count: u8 = 0;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("usb_driver: starting\n");

    // ── Set up channel discovery early (before hardware init) ───
    channel.makeDiscoverable(@enumFromInt(@intFromEnum(keyboard.protocol_id)), 2) catch {
        syscall.write("usb_driver: FAIL makeDiscoverable keyboard\n");
        return;
    };
    // Connect to compositor for mouse events + focus changes
    const mouse_chan = channel.requestConnection(
        @enumFromInt(@intFromEnum(lib.Protocol.compositor)),
        100,
        0,
        10_000_000_000,
    ) orelse {
        syscall.write("usb_driver: FAIL requestConnection compositor timed out\n");
        return;
    };
    const mouse_client = mouse.Client.init(mouse_chan);

    // ── Collect all USB device handles from permission view ─────
    const view: *const [MAX_PERMS]perm_view.UserViewEntry = @ptrFromInt(channel.perm_view_addr);
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

    // ── Initialize all USB controllers ──────────────────────────
    for (usb_handles[0..usb_count], usb_mmio_sizes[0..usb_count]) |handle, mmio_size| {
        const err = controllers[ctrl_count].initFromHandle(handle, mmio_size);
        if (err == .none) {
            ctrl_count += 1;
        }
    }

    // ── Main event loop ─────────────────────────────────────────
    while (true) {
        // Accept new keyboard channels from terminals
        if (channel.pollAnyIncoming()) |chan| {
            if (kb_count < MAX_KB_CHANNELS) {
                kb_channels[kb_count] = chan;
                kb_count += 1;
                syscall.write("usb_driver: keyboard channel connected\n");

                if (kb_count == 1) {
                    active_semantic_id = chan.semantic_id_a;
                }
            }
        }

        // Check for focus change from compositor
        if (mouse_client.recv()) |msg| {
            switch (msg) {
                .focus_change => |sid| {
                    active_semantic_id = sid;
                },
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
                                        kb.processReport(dev, report, findFocusedChannel());
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

fn findFocusedChannel() ?*channel.Channel {
    if (kb_count == 0) return null;

    if (active_semantic_id != 0) {
        for (kb_channels[0..kb_count]) |chan| {
            if (chan.semantic_id_a == active_semantic_id) {
                return chan;
            }
        }
    }

    return kb_channels[0];
}

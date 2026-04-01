const lib = @import("lib");
const dbg = @import("debug_display.zig");
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

    // ── Debug display window ────────────────────────────────────
    const has_debug = dbg.init();
    if (has_debug) {
        dbg.log("usb_driver debug window\n");
        dbg.log("keyboard discoverable: ok\n");
        dbg.log("mouse channel: ok\n");
    }

    // ── Collect all USB device handles from permission view ─────
    const view: *const [MAX_PERMS]perm_view.UserViewEntry = @ptrFromInt(channel.perm_view_addr);
    var usb_handles: [MAX_USB_CONTROLLERS]u64 = .{0} ** MAX_USB_CONTROLLERS;
    var usb_mmio_sizes: [MAX_USB_CONTROLLERS]u32 = .{0} ** MAX_USB_CONTROLLERS;
    var usb_count: u8 = 0;

    if (has_debug) dbg.log("\nperm_view scan:\n");

    for (view, 0..) |*entry, idx| {
        if (entry.entry_type == perm_view.ENTRY_TYPE_EMPTY) continue;
        if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            if (has_debug) {
                dbg.log("  [");
                dbg.logU32(@intCast(idx));
                dbg.log("] dev handle=");
                dbg.logHex(entry.handle);
                dbg.log(" type=");
                dbg.logU32(entry.deviceType());
                dbg.log(" class=");
                dbg.logU32(entry.deviceClass());
                dbg.log(" pci=");
                dbg.logHex(entry.pciVendor());
                dbg.log(":");
                dbg.logHex(entry.pciDevice());
                dbg.log(" bus=");
                dbg.logU32(entry.pciBus());
                dbg.log(" dev=");
                dbg.logU32(entry.pciDev());
                dbg.log(" func=");
                dbg.logU32(entry.pciFunc());
                dbg.log(" size=");
                dbg.logHex(entry.deviceSizeOrPortCount());
                dbg.log("\n");
            }

            if (entry.deviceClass() == @intFromEnum(perms.DeviceClass.usb) and
                usb_count < MAX_USB_CONTROLLERS)
            {
                usb_handles[usb_count] = entry.handle;
                usb_mmio_sizes[usb_count] = entry.deviceSizeOrPortCount();
                usb_count += 1;
            }
        }
    }

    if (has_debug) {
        dbg.log("found ");
        dbg.logU32(usb_count);
        dbg.log(" USB controller(s)\n");
        dbg.flush();
    }

    if (usb_count == 0) {
        if (has_debug) dbg.log("no USB controllers found, waiting...\n");
        syscall.write("usb_driver: no USB controllers\n");
        while (true) syscall.thread_yield();
    }

    // ── Initialize all USB controllers ──────────────────────────
    for (usb_handles[0..usb_count], usb_mmio_sizes[0..usb_count], 0..) |handle, mmio_size, i| {
        if (has_debug) {
            dbg.log("\ninit controller ");
            dbg.logU32(@intCast(i));
            dbg.log(" (handle=");
            dbg.logHex(handle);
            dbg.log(" mmio_size=");
            dbg.logHex(mmio_size);
            dbg.log(")...\n");
            dbg.flush();
        }

        const err = controllers[ctrl_count].initFromHandle(handle, mmio_size);
        if (err == .none) {
            const ctrl = &controllers[ctrl_count];
            const hid_count = ctrl.num_hid_devices;
            if (has_debug) {
                dbg.log("  ok: ");
                dbg.logU32(ctrl.max_ports);
                dbg.log(" ports, ");
                dbg.logU32(hid_count);
                dbg.log(" HID, csz=");
                dbg.logU32(ctrl.context_size);
                dbg.log(" scratch=");
                dbg.logU32(ctrl.num_scratchpad);
                dbg.log("\n");
                // Dump per-port enumeration results
                const port_count = if (ctrl.max_ports < xhci.MAX_PORTS_TRACKED) ctrl.max_ports else xhci.MAX_PORTS_TRACKED;
                var p: u32 = 0;
                while (p < port_count) : (p += 1) {
                    const before = ctrl.port_portsc_before[p];
                    const after = ctrl.readPortsc(p);
                    const status = ctrl.port_status[p];
                    // Only show ports that had CCS or have interesting status
                    if (before & 0x1 != 0 or status != .no_ccs) {
                        dbg.log("    p");
                        dbg.logU32(p);
                        dbg.log(": before=");
                        dbg.logHex(before);
                        dbg.log(" after=");
                        dbg.logHex(after);
                        dbg.log(" -> ");
                        dbg.log(switch (status) {
                            .not_checked => "not_checked",
                            .no_ccs => "no_ccs",
                            .reset_timeout => "reset_timeout",
                            .not_enabled => "not_enabled",
                            .slot_cmd_timeout => "slot_cmd_timeout",
                            .slot_cmd_error => "slot_cmd_error",
                            .address_failed => "address_failed",
                            .desc_timeout => "desc_timeout",
                            .desc_error => "desc_error",
                            .desc_short => "desc_short",
                            .config_failed => "config_failed",
                            .no_hid => "no_hid",
                            .ok => "ok",
                        });
                        if (status == .slot_cmd_error or status == .desc_error) {
                            dbg.log(" cc=");
                            dbg.logU32(ctrl.diag_last_cc);
                        }
                        // Show speed for ports that got past reset
                        if (@intFromEnum(status) >= @intFromEnum(xhci.PortStatus.slot_cmd_timeout)) {
                            const spd = (after >> 10) & 0xF;
                            dbg.log(" spd=");
                            dbg.logU32(spd);
                        }
                        dbg.log("\n");
                    }
                }
                for (ctrl.hidDevices(), 0..) |*dev, j| {
                    dbg.log("    hid[");
                    dbg.logU32(@intCast(j));
                    dbg.log("] slot=");
                    dbg.logU32(dev.slot_id);
                    dbg.log(" ep=");
                    dbg.logU32(dev.ep_dci);
                    dbg.log(" proto=");
                    switch (dev.protocol) {
                        .keyboard => dbg.log("keyboard"),
                        .mouse => dbg.log("mouse"),
                    }
                    dbg.log("\n");
                }
                dbg.flush();
            }
            ctrl_count += 1;
        } else {
            if (has_debug) {
                dbg.log("  FAILED: ");
                dbg.log(switch (err) {
                    .dma_shm_create => "dma_shm_create",
                    .dma_vm_reserve => "dma_vm_reserve",
                    .dma_shm_map => "dma_shm_map",
                    .dma_map => "dma_map",
                    .mmio_vm_reserve => "mmio_vm_reserve",
                    .mmio_map => "mmio_map",
                    .controller_reset => "controller_reset timeout",
                    .controller_cnr => "controller_cnr timeout",
                    .dma_oom => "dma_oom",
                    .controller_start => "controller_start",
                    .noop_timeout => "noop_timeout",
                    .none => unreachable,
                });
                dbg.log(" scratch=");
                dbg.logU32(controllers[ctrl_count].num_scratchpad);
                dbg.log(" csz=");
                dbg.logU32(controllers[ctrl_count].context_size);
                if (err == .controller_start) {
                    const ctrl = &controllers[ctrl_count];
                    dbg.log("\n  pre_start_sts=");
                    dbg.logHex(ctrl.diag_pre_start_sts);
                    dbg.log(" post_start_cmd=");
                    dbg.logHex(ctrl.diag_post_start_cmd);
                    dbg.log(" post_start_sts=");
                    dbg.logHex(ctrl.diag_post_start_sts);
                }
                if (err == .noop_timeout or err == .controller_start) {
                    const ctrl = &controllers[ctrl_count];
                    dbg.log("\n  dma_size=");
                    dbg.logHex(ctrl.dma_region_size);
                    dbg.log("\n  usbcmd=");
                    dbg.logHex(ctrl.diag_usbcmd);
                    dbg.log(" usbsts=");
                    dbg.logHex(ctrl.diag_usbsts);
                    dbg.log("\n  dma_phys=");
                    dbg.logHex(ctrl.dma_phys_base);
                    dbg.log(" cmd_ring_phys=");
                    dbg.logHex(ctrl.cmd_ring_phys);
                    dbg.log("\n  cmd_trb_ctrl=");
                    dbg.logHex(ctrl.diag_cmd_trb_control);
                    dbg.log(" cycle=");
                    dbg.logU32(ctrl.diag_cmd_trb_cycle);
                    dbg.log("\n  evt_trb_ctrl=");
                    dbg.logHex(ctrl.diag_evt_trb_control);
                    dbg.log(" evt_cycle=");
                    dbg.logU32(@intFromBool(ctrl.diag_evt_trb_cycle));
                    dbg.log(" expect=");
                    dbg.logU32(@as(u32, ctrl.evt_ring_cycle));
                    dbg.log("\n  erdp=");
                    dbg.logHex(ctrl.diag_erdp);
                    dbg.log(" iman=");
                    dbg.logHex(ctrl.diag_iman);
                    dbg.log("\n  hccparams1=");
                    dbg.logHex(ctrl.diag_hccparams1);
                    dbg.log(" pagesize=");
                    dbg.logHex(ctrl.diag_pagesize);
                    dbg.log(" db_off=");
                    dbg.logHex(ctrl.diag_db_offset);
                    dbg.log("\n  crcr_readback=");
                    dbg.logHex(ctrl.diag_crcr_lo);
                }
                dbg.log("\n");
                dbg.flush();
            }
        }
    }

    if (has_debug) {
        dbg.log("\n");
        dbg.logU32(ctrl_count);
        dbg.log(" controller(s) active, entering main loop\n");
        dbg.flush();
    }

    // ── Main event loop ─────────────────────────────────────────
    while (true) {
        // Accept new keyboard channels from terminals
        if (channel.pollAnyIncoming()) |chan| {
            if (kb_count < MAX_KB_CHANNELS) {
                kb_channels[kb_count] = chan;
                kb_count += 1;
                syscall.write("usb_driver: keyboard channel connected\n");

                if (has_debug) {
                    dbg.log("kb channel connected (");
                    dbg.logU32(kb_count);
                    dbg.log(" total)\n");
                }

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
                    } else {
                        dbg.log("xfer err slot=");
                        dbg.logU32(slot_id);
                        dbg.log(" ep=");
                        dbg.logU32(ep_id);
                        dbg.log(" cc=");
                        dbg.logU32(@intFromEnum(cc));
                        dbg.log("\n");
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

const lib = @import("lib");
const xhci = @import("xhci.zig");
const kb = @import("keyboard.zig");
const ms = @import("mouse.zig");

const channel = lib.channel;
const keyboard = lib.keyboard;
const mouse = lib.mouse;
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const MAX_KB_CHANNELS = 16;
const MAX_PERMS = 128;

var kb_channels: [MAX_KB_CHANNELS]*channel.Channel = undefined;
var kb_count: u8 = 0;
var active_semantic_id: u64 = 0;

pub fn main(perm_view_addr: u64) void {
    _ = perm_view_addr;
    syscall.write("usb_driver: starting\n");

    // ── Set up channel discovery early (before hardware init) ───
    // The compositor is already waiting for our requestConnection,
    // so we must connect before spending time on xHCI init.
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

    // ── Find USB device in permission view ──────────────────────
    var usb_device_handle: u64 = 0;
    const view: *const [MAX_PERMS]perm_view.UserViewEntry = @ptrFromInt(channel.perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and
            entry.deviceClass() == @intFromEnum(perms.DeviceClass.usb))
        {
            usb_device_handle = entry.handle;
            break;
        }
    }
    if (usb_device_handle == 0) {
        syscall.write("usb_driver: waiting for USB device...\n");
        while (usb_device_handle == 0) {
            for (view) |*entry| {
                if (entry.entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION and
                    entry.deviceClass() == @intFromEnum(perms.DeviceClass.usb))
                {
                    usb_device_handle = entry.handle;
                    break;
                }
            }
            if (usb_device_handle == 0) syscall.thread_yield();
        }
    }
    // ── Allocate DMA region ─────────────────────────────────────
    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();
    const dma_shm = syscall.shm_create_with_rights(xhci.DMA_REGION_SIZE, shm_rights);
    if (dma_shm <= 0) {
        syscall.write("usb_driver: DMA shm_create failed\n");
        return;
    }

    const dma_vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const dma_vm = syscall.vm_reserve(0, xhci.DMA_REGION_SIZE, dma_vm_rights);
    if (dma_vm.val < 0) {
        syscall.write("usb_driver: DMA vm_reserve failed\n");
        return;
    }
    if (syscall.shm_map(@intCast(dma_shm), @intCast(dma_vm.val), 0) != 0) {
        syscall.write("usb_driver: DMA shm_map failed\n");
        return;
    }

    const dma_result = syscall.dma_map(usb_device_handle, @intCast(dma_shm));
    if (dma_result < 0) {
        syscall.write("usb_driver: DMA map failed\n");
        return;
    }
    const dma_phys: u64 = @bitCast(dma_result);

    // ── Map xHCI MMIO ───────────────────────────────────────────
    const mmio_size: u64 = 65536;
    const mmio_vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .mmio = true,
    }).bits();
    const mmio_vm = syscall.vm_reserve(0, mmio_size, mmio_vm_rights);
    if (mmio_vm.val < 0) {
        syscall.write("usb_driver: MMIO vm_reserve failed\n");
        return;
    }
    if (syscall.mmio_map(usb_device_handle, @intCast(mmio_vm.val), 0) != 0) {
        syscall.write("usb_driver: MMIO map failed\n");
        return;
    }

    // ── Initialize xHCI controller ──────────────────────────────
    const result = xhci.init(mmio_vm.val2, dma_vm.val2, dma_phys) orelse {
        syscall.write("usb_driver: controller init failed\n");
        return;
    };

    // ── Main event loop ─────────────────────────────────────────
    while (true) {
        // Accept new keyboard channels from terminals
        if (channel.pollAnyIncoming()) |chan| {
            if (kb_count < MAX_KB_CHANNELS) {
                kb_channels[kb_count] = chan;
                kb_count += 1;
                syscall.write("usb_driver: keyboard channel connected\n");

                // Default focus to first connected channel
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

        // Poll xHCI event ring
        if (xhci.pollEvent()) |evt| {
            if (evt.trbType() == .transfer_event) {
                const cc = evt.completionCode();
                if (cc == .success or cc == .short_packet) {
                    const slot_id = evt.slotId();
                    for (result.hid_devices) |*dev| {
                        if (dev.slot_id == slot_id and dev.active) {
                            const report = xhci.getReportData(slot_id);

                            switch (dev.protocol) {
                                .keyboard => {
                                    if (findFocusedChannel()) |chan| {
                                        kb.processReport(dev, report, chan);
                                    }
                                },
                                .mouse => {
                                    ms.processReport(report, &mouse_client);
                                },
                            }

                            xhci.queueInterruptIn(slot_id, dev.ep_dci);
                            xhci.ringDoorbell(slot_id, dev.ep_dci);
                            break;
                        }
                    }
                }
            }
            xhci.advanceEventRing();
        } else {
            syscall.thread_yield();
        }
    }
}

fn findFocusedChannel() ?*channel.Channel {
    if (kb_count == 0) return null;

    // Find channel matching active_semantic_id
    if (active_semantic_id != 0) {
        for (kb_channels[0..kb_count]) |chan| {
            if (chan.semantic_id_a == active_semantic_id) {
                return chan;
            }
        }
    }

    // Fallback to first channel
    return kb_channels[0];
}

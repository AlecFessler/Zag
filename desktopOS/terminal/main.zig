const lib = @import("lib");
const commands = @import("commands.zig");
const input = @import("input.zig");
const render = @import("render.zig");

const channel = lib.channel;
const display = lib.display;
const keyboard = lib.keyboard;
const syscall = lib.syscall;

const Channel = channel.Channel;

const DEFAULT_SHM_SIZE: u64 = 4 * syscall.PAGE4K;

pub fn main(perm_view_addr: u64) void {
    syscall.write("terminal: starting\n");

    // Find compositor and connect for display
    var comp_handle: u64 = 0;
    while (comp_handle == 0) {
        comp_handle = channel.findBroadcastHandle(perm_view_addr, .compositor) orelse 0;
        if (comp_handle == 0) syscall.thread_yield();
    }
    const display_conn = Channel.connectAsA(comp_handle, .compositor, display.SHM_SIZE) orelse {
        syscall.write("terminal: FAIL connectAsA compositor\n");
        return;
    };
    var display_client = display.Client.init(display_conn.chan);
    syscall.write("terminal: display channel connected to compositor\n");

    // Find usb_keyboard and connect for keyboard input
    var kb_handle: u64 = 0;
    while (kb_handle == 0) {
        kb_handle = channel.findBroadcastHandle(perm_view_addr, .usb_keyboard) orelse 0;
        if (kb_handle == 0) syscall.thread_yield();
    }
    const kb_conn = Channel.connectAsA(kb_handle, .usb_keyboard, DEFAULT_SHM_SIZE) orelse {
        syscall.write("terminal: FAIL connectAsA usb_keyboard\n");
        return;
    };
    const kb_chan = kb_conn.chan;
    syscall.write("terminal: keyboard channel connected to usb_driver\n");

    // Receive render target info from compositor
    var retries: u32 = 0;
    while (retries < 50000) : (retries += 1) {
        if (display_client.recv()) |msg| {
            switch (msg) {
                .render_target => |info| {
                    render.updateDisplayInfo(info.width, info.height, info.stride, info.format);
                    break;
                },
                else => {},
            }
        }
        syscall.thread_yield();
    } else {
        syscall.write("terminal: FAIL no render target info\n");
        return;
    }

    // Allocate frame buffer and render initial frame
    render.allocFrameBuffer();

    render.appendHistory("zagOS terminal v0.1\n");
    render.renderFrame();

    display_client.sendFrame(render.frame_bytes[0..render.frame_byte_size]) catch {
        syscall.write("terminal: FAIL sendFrame\n");
        return;
    };

    // Main event loop
    var needs_redraw: bool = false;
    while (!commands.should_exit) {
        // Check for display protocol messages (resize, pane notifications)
        if (display_client.recv()) |msg| {
            switch (msg) {
                .window_resized, .render_target => |info| {
                    render.updateDisplayInfo(info.width, info.height, info.stride, info.format);
                    render.allocFrameBuffer();
                    needs_redraw = true;
                },
                .pane_created => {},
                .pane_activated => {},
            }
        }

        if (keyboard.Client.recv(kb_chan)) |msg| {
            switch (msg) {
                .key => |ev| {
                    if (ev.state == .pressed) {
                        input.handleKeyPress(ev.keycode, ev.modifiers, &display_client);
                        needs_redraw = true;
                    }
                },
            }
        }

        if (needs_redraw) {
            render.renderFrame();
            display_client.sendFrame(render.frame_bytes[0..render.frame_byte_size]) catch {};
            needs_redraw = false;
        }

        syscall.thread_yield();
    }

    // Notify compositor we're exiting
    display_client.sendExit() catch {};
}

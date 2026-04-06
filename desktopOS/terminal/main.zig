const lib = @import("lib");
const commands = @import("commands.zig");
const input = @import("input.zig");
const render = @import("render.zig");

const display = lib.display;
const filesystem = lib.filesystem;
const keyboard = lib.keyboard;
const syscall = lib.syscall;

pub fn main(perm_view_addr: u64) void {
    // Connect to display server
    var display_client_opt: ?display.Client = null;
    while (display_client_opt == null) {
        display_client_opt = display.connectToServer(perm_view_addr) catch |err| switch (err) {
            error.ServerNotFound => null,
            error.ChannelFailed => return,
        };
        if (display_client_opt == null) syscall.thread_yield();
    }
    var display_client = display_client_opt.?;

    // Connect to keyboard server
    var kb_client_opt: ?keyboard.Client = null;
    while (kb_client_opt == null) {
        kb_client_opt = keyboard.connectToServer(perm_view_addr) catch |err| switch (err) {
            error.ServerNotFound => null,
            error.ChannelFailed => return,
        };
        if (kb_client_opt == null) syscall.thread_yield();
    }
    const kb_client = kb_client_opt.?;

    // Connect to filesystem server
    var fs_client_opt: ?filesystem.Client = null;
    var fs_attempts: u32 = 0;
    while (fs_client_opt == null and fs_attempts < 500_000) : (fs_attempts += 1) {
        fs_client_opt = filesystem.connectToServer(perm_view_addr) catch |err| switch (err) {
            error.ServerNotFound => null,
            error.ChannelFailed => null,
        };
        if (fs_client_opt == null) syscall.thread_yield();
    }
    if (fs_client_opt) |*fc| {
        commands.setFsClient(fc);
    }

    // Wait for render target info and set up framebuffers
    if (!waitForRenderTarget(&display_client)) return;

    render.appendHistory("zagOS terminal v0.1\n");
    renderAndPresent(&display_client);

    // Main event loop
    var needs_redraw: bool = false;
    while (!commands.should_exit) {
        // Check for display protocol messages
        if (display_client.recv()) |msg| {
            switch (msg) {
                .window_resized => |info| {
                    display_client.teardownFramebuffers();
                    display_client.setupFramebuffers(info) catch return;
                    if (!waitForFbReady(&display_client)) return;
                    needs_redraw = true;
                },
                .render_target => |info| {
                    display_client.teardownFramebuffers();
                    display_client.setupFramebuffers(info) catch return;
                    if (!waitForFbReady(&display_client)) return;
                    needs_redraw = true;
                },
                .fb_ready => {},
            }
        }

        if (kb_client.recv()) |msg| {
            switch (msg) {
                .key => |ev| {
                    if (ev.state == .pressed) {
                        input.handleKeyPress(ev.keycode, ev.modifiers);
                        needs_redraw = true;
                    }
                },
            }
        }

        if (needs_redraw) {
            renderAndPresent(&display_client);
            needs_redraw = false;
        }

        syscall.thread_yield();
    }
}

fn waitForRenderTarget(client: *display.Client) bool {
    var retries: u32 = 0;
    while (retries < 50000) : (retries += 1) {
        if (client.recv()) |msg| {
            switch (msg) {
                .render_target => |info| {
                    client.setupFramebuffers(info) catch return false;
                    return waitForFbReady(client);
                },
                else => {},
            }
        }
        syscall.thread_yield();
    }
    return false;
}

fn waitForFbReady(client: *display.Client) bool {
    var retries: u32 = 0;
    while (retries < 50000) : (retries += 1) {
        if (client.recv()) |msg| {
            switch (msg) {
                .fb_ready => return true,
                else => {},
            }
        }
        syscall.thread_yield();
    }
    return false;
}

fn renderAndPresent(client: *display.Client) void {
    render.renderFrame(client.pixelsAsU32(), client.width, client.height, client.stride);
    client.sendFrameReady() catch {};
}

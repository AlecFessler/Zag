const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const MAX_CLIENTS = 8;
const MAX_MAPPED = 16;

var compositor_chan: ?channel_mod.Channel = null;
var client_chans: [MAX_CLIENTS]?channel_mod.Channel = .{null} ** MAX_CLIENTS;
var num_clients: u32 = 0;

// Track SHM handles we've already mapped so we don't re-map them.
var mapped_handles: [MAX_MAPPED]u64 = .{0} ** MAX_MAPPED;
var num_mapped: u32 = 0;

fn isHandleMapped(handle: u64) bool {
    for (mapped_handles[0..num_mapped]) |h| {
        if (h == handle) return true;
    }
    return false;
}

fn recordMapped(handle: u64) void {
    if (num_mapped < MAX_MAPPED) {
        mapped_handles[num_mapped] = handle;
        num_mapped += 1;
    }
}

/// Find and map the next unmapped data SHM from the perm view.
fn findAndMapNextDataShm(perm_view_addr: u64) ?struct { header: *channel_mod.ChannelHeader, handle: u64 } {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    for (view) |*entry| {
        if (entry.entry_type != pv.ENTRY_TYPE_SHARED_MEMORY) continue;
        if (entry.field0 <= shm_protocol.COMMAND_SHM_SIZE) continue;
        if (isHandleMapped(entry.handle)) continue;

        const vm_rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
            .execute = true,
            .shareable = true,
        }).bits();
        const vm = syscall.vm_reserve(0, entry.field0, vm_rights);
        if (vm.val < 0) continue;
        if (syscall.shm_map(entry.handle, @intCast(vm.val), 0) != 0) continue;

        recordMapped(entry.handle);
        return .{ .header = @ptrFromInt(vm.val2), .handle = entry.handle };
    }
    return null;
}

/// Count data SHMs currently visible in the perm view.
fn countDataShms(perm_view_addr: u64) u32 {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var count: u32 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and entry.field0 > shm_protocol.COMMAND_SHM_SIZE) {
            count += 1;
        }
    }
    return count;
}

fn waitForDataShm(perm_view_addr: u64, min_count: u32) void {
    var attempts: u32 = 0;
    while (attempts < 50_000) : (attempts += 1) {
        if (countDataShms(perm_view_addr) >= min_count) return;
        syscall.thread_yield();
    }
}

fn forwardToCompositor(data: []const u8) void {
    if (compositor_chan) |*c| {
        _ = c.send(data);
    }
}

/// Map all unmapped data SHMs as client channels.
fn mapNewClientShms(perm_view_addr: u64) void {
    while (true) {
        const result = findAndMapNextDataShm(perm_view_addr) orelse return;
        if (num_clients < MAX_CLIENTS) {
            client_chans[num_clients] = channel_mod.Channel.openAsSideB(result.header);
            if (client_chans[num_clients] != null) {
                num_clients += 1;
                forwardToCompositor("desktop_env: client connected\n");
            }
        }
    }
}

pub fn main(perm_view_addr: u64) void {
    // desktop_env starting

    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("desktop_env: no command channel\n");
        return;
    };

    // Record the command channel SHM as "mapped" so we skip it later.
    // Find it in the perm view and record its handle.
    {
        const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
        for (view) |*entry| {
            if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and entry.field0 <= shm_protocol.COMMAND_SHM_SIZE) {
                recordMapped(entry.handle);
                break;
            }
        }
    }

    // Count existing data SHMs before requesting compositor connection.
    // Boot info SHM from root service may already be present.
    const pre_compositor_shm_count = countDataShms(perm_view_addr);

    // Request connection to compositor
    const comp_entry = cmd.requestConnection(shm_protocol.ServiceId.COMPOSITOR) orelse {
        syscall.write("desktop_env: compositor connection not allowed\n");
        return;
    };
    if (!cmd.waitForConnection(comp_entry)) {
        syscall.write("desktop_env: compositor connection failed\n");
        return;
    }

    // Wait for a new data SHM to appear (the compositor data channel)
    waitForDataShm(perm_view_addr, pre_compositor_shm_count + 1);

    // Map all newly appeared data SHMs. The compositor channel is the one
    // initialized by the broker (no data queued yet). Client channels
    // (e.g., boot info from root service) may have pre-queued data.
    // Try each as Side B: if it has data queued, it's a client; otherwise
    // it's the compositor channel.
    {
        while (true) {
            const result = findAndMapNextDataShm(perm_view_addr) orelse break;
            var ch = channel_mod.Channel.openAsSideB(result.header) orelse continue;
            // Peek: if the ring has data already, it's a pre-populated client channel.
            if (ch.hasMessage()) {
                // Client channel (e.g., boot info)
                if (num_clients < MAX_CLIENTS) {
                    client_chans[num_clients] = ch;
                    num_clients += 1;
                    // client connected
                }
            } else {
                // Empty ring = freshly brokered compositor channel
                compositor_chan = ch;
            }
        }
    }

    if (compositor_chan == null) {
        syscall.write("desktop_env: failed to open compositor channel\n");
        return;
    }
    forwardToCompositor("desktop_env: started\n");

    // Forward any boot info already in client channels
    {
        var recv_buf: [1024]u8 = undefined;
        var i: u32 = 0;
        while (i < num_clients) : (i += 1) {
            if (client_chans[i]) |*c| {
                while (c.recv(&recv_buf)) |len| {
                    forwardToCompositor(recv_buf[0..len]);
                }
            }
        }
    }

    // Request connection to router
    var router_chan: ?channel_mod.Channel = null;
    const pre_router_shm_count = countDataShms(perm_view_addr);
    if (cmd.requestConnection(shm_protocol.ServiceId.ROUTER)) |router_entry| {
        if (cmd.waitForConnection(router_entry)) {
            // router connection established
            waitForDataShm(perm_view_addr, pre_router_shm_count + 1);
            if (findAndMapNextDataShm(perm_view_addr)) |result| {
                router_chan = channel_mod.Channel.openAsSideB(result.header);
                if (router_chan != null) {
                    _ = router_chan.?.send(&[_]u8{@truncate(shm_protocol.ServiceId.DESKTOP_ENV)});
                    forwardToCompositor("desktop_env: router connected\n");
                }
            }
        }
    }

    // Main loop: poll router + client channels, forward to compositor
    var recv_buf: [1024]u8 = undefined;

    while (true) {
        var got_data = false;

        // Check for new client channels periodically
        mapNewClientShms(perm_view_addr);

        // Poll router channel
        if (router_chan) |*rc| {
            while (rc.recv(&recv_buf)) |len| {
                forwardToCompositor(recv_buf[0..len]);
                got_data = true;
            }
        }

        // Poll all client channels
        var i: u32 = 0;
        while (i < num_clients) : (i += 1) {
            if (client_chans[i]) |*c| {
                while (c.recv(&recv_buf)) |len| {
                    forwardToCompositor(recv_buf[0..len]);
                    got_data = true;
                }
            }
        }

        if (!got_data) {
            if (router_chan) |*rc| {
                rc.waitForMessage(50_000_000);
            } else if (num_clients > 0) {
                if (client_chans[0]) |*c| {
                    c.waitForMessage(50_000_000);
                }
            } else {
                const current = @atomicLoad(u64, &cmd.reply_flag, .acquire);
                _ = syscall.futex_wait(&cmd.reply_flag, current, 50_000_000);
            }
        }
    }
}

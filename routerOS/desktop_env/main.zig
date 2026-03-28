const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const MAX_CLIENTS = 8;

var compositor_chan: ?channel_mod.Channel = null;
var client_chans: [MAX_CLIENTS]?channel_mod.Channel = .{null} ** MAX_CLIENTS;
var num_clients: u32 = 0;

fn mapDataChannel(shm_handle: u64, shm_size: u64) ?*channel_mod.ChannelHeader {
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm = syscall.vm_reserve(0, shm_size, vm_rights);
    if (vm.val < 0) return null;
    if (syscall.shm_map(shm_handle, @intCast(vm.val), 0) != 0) return null;
    return @ptrFromInt(vm.val2);
}

fn forwardToCompositor(data: []const u8) void {
    if (compositor_chan) |*c| {
        _ = c.send(data);
    }
}

fn checkNewClients(cmd: *shm_protocol.CommandChannel) void {
    for (cmd.connections[0..cmd.num_connections]) |*entry| {
        if (@as(*volatile u32, &entry.status).* == @intFromEnum(shm_protocol.ConnectionStatus.connected)) {
            if (entry.shm_handle == 0) continue;
            // Check if we already mapped this connection
            var already_mapped = false;
            if (entry.service_id == shm_protocol.ServiceId.COMPOSITOR) {
                already_mapped = compositor_chan != null;
            } else {
                for (client_chans[0..num_clients]) |existing| {
                    if (existing != null) {
                        already_mapped = true;
                        break;
                    }
                }
            }
            if (already_mapped) continue;

            if (mapDataChannel(entry.shm_handle, entry.shm_size)) |header| {
                if (entry.service_id == shm_protocol.ServiceId.COMPOSITOR) {
                    // We requested this connection — open as side A
                    compositor_chan = channel_mod.Channel.openAsSideB(header);
                    if (compositor_chan != null) {
                        syscall.write("desktop_env: compositor connected\n");
                        forwardToCompositor("desktop_env: started\n");
                    }
                } else {
                    // Incoming connection from another process — open as side B
                    if (num_clients < MAX_CLIENTS) {
                        client_chans[num_clients] = channel_mod.Channel.openAsSideB(header);
                        if (client_chans[num_clients] != null) {
                            num_clients += 1;
                            syscall.write("desktop_env: client connected\n");
                            forwardToCompositor("desktop_env: client connected\n");
                        }
                    }
                }
            }
        }
    }
}

pub fn main(perm_view_addr: u64) void {
    syscall.write("desktop_env: starting\n");

    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("desktop_env: no command channel\n");
        return;
    };

    // Request connection to compositor
    const comp_entry = cmd.requestConnection(shm_protocol.ServiceId.COMPOSITOR) orelse {
        syscall.write("desktop_env: compositor connection not allowed\n");
        return;
    };
    if (!cmd.waitForConnection(comp_entry)) {
        syscall.write("desktop_env: compositor connection failed\n");
        return;
    }

    // Map compositor channel
    checkNewClients(cmd);

    if (compositor_chan == null) {
        syscall.write("desktop_env: failed to open compositor channel\n");
        return;
    }

    // Request connection to router
    var router_chan: ?channel_mod.Channel = null;
    if (cmd.requestConnection(shm_protocol.ServiceId.ROUTER)) |router_entry| {
        if (cmd.waitForConnection(router_entry)) {
            syscall.write("desktop_env: router connection established\n");
            // Map the router channel
            if (router_entry.shm_handle != 0) {
                if (mapDataChannel(router_entry.shm_handle, router_entry.shm_size)) |header| {
                    if (channel_mod.Channel.openAsSideB(header)) |ch| {
                        router_chan = ch;
                        // Send our service ID so the router knows who we are
                        _ = router_chan.?.send(&[_]u8{@truncate(shm_protocol.ServiceId.DESKTOP_ENV)});
                        forwardToCompositor("desktop_env: router connected\n");
                    }
                }
            }
        }
    }

    // Main loop: poll router + client channels, forward to compositor
    var recv_buf: [1024]u8 = undefined;

    while (true) {
        var got_data = false;

        // Check for new incoming connections
        checkNewClients(cmd);

        // Poll router channel
        if (router_chan) |*rc| {
            while (rc.recv(&recv_buf)) |len| {
                forwardToCompositor(recv_buf[0..len]);
                got_data = true;
            }
        }

        // Poll all client channels (e.g., root service boot info)
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
            // Wait briefly for data
            if (router_chan) |*rc| {
                rc.waitForMessage(50_000_000); // 50ms
            } else if (num_clients > 0) {
                if (client_chans[0]) |*c| {
                    c.waitForMessage(50_000_000);
                }
            } else {
                const current = @atomicLoad(u64, &cmd.wake_flag, .acquire);
                _ = syscall.futex_wait(&cmd.wake_flag, current, 50_000_000);
            }
        }
    }
}

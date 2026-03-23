const lib = @import("lib");

const channel_mod = lib.channel;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const BENCH_SENDER_ID = 0xFE;

fn mapShmAsSideB(handle: u64, size: u64) ?channel_mod.Channel {
    const vm_rights = (perms.VmReservationRights{
        .read = true, .write = true, .shareable = true,
    }).bits();
    const vm = syscall.vm_reserve(0, size, vm_rights);
    if (vm.val < 0) return null;
    if (syscall.shm_map(handle, @intCast(vm.val), 0) != 0) return null;
    const header: *channel_mod.ChannelHeader = @ptrFromInt(vm.val2);
    return channel_mod.Channel.openAsSideB(header);
}

pub fn main(perm_view_addr: u64) void {
    syscall.write("bench_echo: started\n");

    const cmd = shm_protocol.mapCommandChannel(perm_view_addr) orelse {
        syscall.write("bench_echo: no command channel\n");
        return;
    };

    const entry = cmd.requestConnection(BENCH_SENDER_ID) orelse {
        syscall.write("bench_echo: connection not allowed\n");
        return;
    };
    if (!cmd.waitForConnection(entry)) {
        syscall.write("bench_echo: connection failed\n");
        return;
    }
    syscall.write("bench_echo: connected\n");

    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var data_handle: u64 = 0;
    var data_size: u64 = 0;
    while (data_handle == 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 > shm_protocol.COMMAND_SHM_SIZE)
            {
                data_handle = e.handle;
                data_size = e.field0;
                break;
            }
        }
        if (data_handle == 0) syscall.thread_yield();
    }

    var chan = mapShmAsSideB(data_handle, data_size) orelse {
        syscall.write("bench_echo: channel map failed\n");
        return;
    };

    var buf: [2048]u8 = undefined;
    while (true) {
        chan.waitForMessage();
        while (chan.hasMessage()) {
            if (chan.recv(&buf)) |len| {
                if (len == 4 and buf[0] == 'D' and buf[1] == 'O' and buf[2] == 'N' and buf[3] == 'E') {
                    syscall.write("bench_echo: done\n");
                    return;
                }
                _ = chan.send(buf[0..len]);
            }
        }
    }
}

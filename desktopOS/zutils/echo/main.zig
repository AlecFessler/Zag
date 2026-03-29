const lib = @import("lib");

const channel_mod = lib.channel;
const fb_proto = lib.framebuffer;
const perms = lib.perms;
const pv = lib.perm_view;
const shm_protocol = lib.shm_protocol;
const syscall = lib.syscall;

const MAX_PERMS = 128;
const MAX_TIMEOUT: u64 = @bitCast(@as(i64, -1));

pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Find the data channel SHM granted by the terminal
    var data_shm_handle: u64 = 0;
    var data_shm_size: u64 = 0;
    while (data_shm_handle == 0) {
        for (view) |*e| {
            if (e.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY and
                e.field0 > shm_protocol.COMMAND_SHM_SIZE and
                e.field0 != fb_proto.FRAMEBUFFER_SHM_SIZE)
            {
                data_shm_handle = e.handle;
                data_shm_size = e.field0;
                break;
            }
        }
        if (data_shm_handle == 0) pv.waitForChange(perm_view_addr, MAX_TIMEOUT);
    }
    if (data_shm_handle == 0) {
        syscall.write("echo: no SHM found\n");
        return;
    }

    // Map the data channel
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .execute = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.vm_reserve(0, data_shm_size, vm_rights);
    if (vm_result.val < 0) {
        syscall.write("echo: vm_reserve failed\n");
        return;
    }
    if (syscall.shm_map(data_shm_handle, @intCast(vm_result.val), 0) != 0) {
        syscall.write("echo: shm_map failed\n");
        return;
    }

    const chan_header: *channel_mod.ChannelHeader = @ptrFromInt(vm_result.val2);
    var chan = channel_mod.Channel.openAsSideB(chan_header) orelse {
        syscall.write("echo: channel open failed\n");
        return;
    };

    // Read input, echo it back
    var buf: [256]u8 = undefined;
    while (true) {
        if (chan.recv(&buf)) |len| {
            _ = chan.send(buf[0..len]);
            return;
        }
        chan.waitForMessage(MAX_TIMEOUT);
    }
}

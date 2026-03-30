const lib = @import("lib");

const channel = lib.channel;
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const MAX_PERMS = 128;

pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]perm_view.UserViewEntry = @ptrFromInt(perm_view_addr);

    // Find the data channel SHM granted by the terminal.
    // It's the only SHM entry in our perm_view.
    var data_shm_handle: u64 = 0;
    var data_shm_size: u64 = 0;
    var attempts: u32 = 0;
    while (data_shm_handle == 0 and attempts < 100000) : (attempts += 1) {
        for (view) |*e| {
            if (e.entry_type == perm_view.ENTRY_TYPE_SHARED_MEMORY and e.field0 > 0) {
                data_shm_handle = e.handle;
                data_shm_size = e.field0;
                break;
            }
        }
        if (data_shm_handle == 0) syscall.thread_yield();
    }
    if (data_shm_handle == 0) {
        syscall.write("echo: no SHM found\n");
        return;
    }

    // Map the data channel
    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
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

    // Open channel as side B (child/receiver)
    const chan: *channel.Channel = @ptrFromInt(vm_result.val2);

    // Read input from side A, echo it back on side B
    var buf: [256]u8 = undefined;
    var retries: u32 = 0;
    while (retries < 50000) : (retries += 1) {
        if (chan.dequeue(.B, &buf)) |len| {
            chan.enqueue(.B, buf[0..len]) catch {
                syscall.write("echo: enqueue failed\n");
                return;
            };
            return;
        }
        syscall.thread_yield();
    }
    syscall.write("echo: timeout waiting for input\n");
}

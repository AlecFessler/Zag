const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Initialized .data variable — linker places this in .data section (not BSS).
var data_sentinel: u64 = 0xCAFE_BABE_DEAD_BEEF;

pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        // First boot: corrupt the .data variable, then exit to trigger restart.
        data_sentinel = 0x1111_2222_3333_4444;
    } else {
        // After restart: .data should have been reloaded from ELF.
        // Wait for parent to call us, then reply with the current value.
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;
        _ = syscall.ipc_reply(&.{data_sentinel});
    }
}

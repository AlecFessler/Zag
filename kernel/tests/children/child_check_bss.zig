const lib = @import("lib");

const pv = lib.perm_view;
const syscall = lib.syscall;

const MAX_PERMS = 128;

/// Zero-initialized global — linker places this in BSS.
var bss_sentinel: u64 = 0;

pub fn main(perm_view_addr: u64) void {
    const view: *const [MAX_PERMS]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    const restart_count = view[0].processRestartCount();

    if (restart_count == 0) {
        // First boot: write a non-zero sentinel into BSS, then exit to trigger restart.
        bss_sentinel = 0xDEAD_BEEF_CAFE_BABE;
    } else {
        // After restart: BSS should have been decommitted and demand-faulted fresh (zeroed).
        // Wait for parent to call us, then reply with the current bss_sentinel value.
        var msg: syscall.IpcMessage = .{};
        if (syscall.ipc_recv(true, &msg) != 0) return;
        _ = syscall.ipc_reply(&.{bss_sentinel});
    }
}

const builtin = @import("builtin");
const lib = @import("lib");

const perms = lib.perms;
const pv = lib.perm_view;
const syscall = lib.syscall;

/// Arch-specific `ret` encoding. x86: `0xC3` (1 byte near RET).
/// aarch64: `0xD65F03C0` (4 bytes, little-endian) — `ret` to x30.
const RET_BYTES: []const u8 = switch (builtin.cpu.arch) {
    .x86_64 => &[_]u8{0xC3},
    .aarch64 => &[_]u8{ 0xC0, 0x03, 0x5F, 0xD6 },
    else => @compileError("unsupported arch"),
};

/// Receives a read+write (no execute) SHM via cap transfer. Writes an
/// arch-appropriate `ret` encoding into the mapping and jumps to it,
/// triggering invalid_execute on the SHM region.
pub fn main(perm_view_addr: u64) void {
    var msg: syscall.IpcMessage = .{};
    if (syscall.ipc_recv(true, &msg) != 0) return;
    _ = syscall.ipc_reply(&.{});

    const view: *const [128]pv.UserViewEntry = @ptrFromInt(perm_view_addr);
    var shm_handle: u64 = 0;
    var shm_size: u64 = 0;
    for (view) |*entry| {
        if (entry.entry_type == pv.ENTRY_TYPE_SHARED_MEMORY) {
            shm_handle = entry.handle;
            shm_size = entry.field0;
            break;
        }
    }
    if (shm_handle == 0 or shm_size == 0) return;

    const vm_rights = (perms.VmReservationRights{
        .read = true,
        .write = true,
        .shareable = true,
    }).bits();
    const vm_result = syscall.mem_reserve(0, shm_size, vm_rights);
    if (vm_result.val < 0) return;
    if (syscall.mem_shm_map(shm_handle, @intCast(vm_result.val), 0) != 0) return;

    const dest: [*]volatile u8 = @ptrFromInt(vm_result.val2);
    for (RET_BYTES, 0..) |byte, i| dest[i] = byte;
    const func: *const fn () void = @ptrFromInt(vm_result.val2);
    func();
}

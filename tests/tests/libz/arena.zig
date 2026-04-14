const std = @import("std");

const perms = @import("perms.zig");
const syscall = @import("syscall.zig");

/// Bump allocator backed by a demand-paged VM reservation.
/// Physical pages are faulted in by the kernel on first access, so a
/// large reservation (e.g. 1 GiB) costs nothing until actually touched.
/// Implements `std.mem.Allocator` for use with standard containers.
pub const Arena = struct {
    start_addr: u64,
    free_addr: u64,
    end_addr: u64,

    /// Create an arena backed by a new VM reservation of `size` bytes.
    pub fn init(size: u64) ?Arena {
        const rights = (perms.VmReservationRights{
            .read = true,
            .write = true,
        }).bits();
        const result = syscall.mem_reserve(0, size, rights);
        if (result.val < 0) return null;
        return .{
            .start_addr = result.val2,
            .free_addr = result.val2,
            .end_addr = result.val2 + size,
        };
    }

    pub fn allocator(self: *Arena) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ptr: *anyopaque,
        len: u64,
        alignment: std.mem.Alignment,
        ret_addr: u64,
    ) ?[*]u8 {
        _ = ret_addr;
        const self: *Arena = @ptrCast(@alignCast(ptr));

        const aligned = std.mem.alignForward(
            u64,
            self.free_addr,
            alignment.toByteUnits(),
        );
        const next_free = aligned + len;

        if (next_free > self.end_addr) {
            return null;
        }

        self.free_addr = next_free;
        return @ptrFromInt(aligned);
    }

    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return false;
    }

    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: u64,
        ret_addr: u64,
    ) ?[*]u8 {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        return null;
    }

    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: u64,
    ) void {
        _ = ptr;
        _ = buf;
        _ = alignment;
        _ = ret_addr;
    }
};

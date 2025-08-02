const std = @import("std");

pub fn FreeList(comptime T: type) type {
    return struct {
        const Self = @This();

        ptr: *anyopaque,
        vtable: *const VTable,

        pub const VTable = struct {
            getNextFree: *const fn (*anyopaque) ?[*]u8,

            setFree: *const fn (*anyopaque, [*]u8) void,

            isFree: *const fn (*anyopaque, [*]u8) bool,
        };

        pub fn getNextFree(self: Self) ?T {
            const maybe_next_free = self.vtable.getNextFree(self.ptr);
            if (maybe_next_free) |next_free| {
                switch (@typeInfo(T)) {
                    .int => return @intFromPtr(next_free),
                    .pointer => return @alignCast(@ptrCast(next_free)),
                    else => @compileError("FreeList expects integer or pointer types only"),
                }
            } else return null;
        }

        pub fn setFree(self: Self, addr: T) void {
            switch (@typeInfo(T)) {
                .int => {
                    self.vtable.setFree(
                        self.ptr,
                        @ptrFromInt(addr),
                    );
                },
                .pointer => {
                    self.vtable.setFree(
                        self.ptr,
                        @ptrCast(addr),
                    );
                },
                else => @compileError("FreeList expects integer or pointer types only"),
            }
        }

        pub fn isFree(self: Self, addr: T) bool {
            switch (@typeInfo(T)) {
                .int => {
                    return self.vtable.isFree(
                        self.ptr,
                        @ptrFromInt(addr),
                    );
                },
                .pointer => {
                    return self.vtable.isFree(
                        self.ptr,
                        @ptrCast(addr),
                    );
                },
                else => @compileError("FreeList expects integer or pointer types only"),
            }
        }
    };
}

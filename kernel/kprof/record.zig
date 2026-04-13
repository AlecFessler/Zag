pub const RECORD_SIZE: usize = 32;

pub const Kind = enum(u8) {
    trace_enter = 1,
    trace_exit = 2,
    trace_point = 3,
    sample = 4,
};

pub const Record = extern struct {
    tsc: u64,
    kind: u8,
    cpu: u8,
    _pad: u16,
    id: u32,
    rip: u64,
    arg: u64,
};

comptime {
    const std = @import("std");
    std.debug.assert(@sizeOf(Record) == RECORD_SIZE);
}

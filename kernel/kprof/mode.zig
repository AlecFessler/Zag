const build_options = @import("build_options");
const std = @import("std");

pub const Mode = enum { none, trace, sample };

pub const active: Mode = blk: {
    const s = build_options.kernel_profile;
    if (std.mem.eql(u8, s, "none")) break :blk .none;
    if (std.mem.eql(u8, s, "trace")) break :blk .trace;
    if (std.mem.eql(u8, s, "sample")) break :blk .sample;
    @compileError("invalid kernel_profile build option");
};

pub const trace_enabled: bool = active == .trace;
pub const sample_enabled: bool = active == .sample;
pub const any_enabled: bool = active != .none;

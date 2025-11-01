const paging = @import("paging.zig");
const serial = @import("serial.zig");
const std = @import("std");

const VAddr = paging.VAddr;

const xsdpError = error{
    InvalidSignature,
    InvalidSize,
    InvalidChecksum,
};

pub fn validateXSDP(xsdp_virt: VAddr) !void {
    const xsdp_bytes: [*]const u8 = @ptrFromInt(xsdp_virt.addr);

    if (!std.mem.eql(
        u8,
        xsdp_bytes[0..8],
        "RSD PTR ",
    )) return xsdpError.InvalidSignature;

    const len = std.mem.readInt(
        u32,
        xsdp_bytes[20..24],
        .little,
    );
    if (len < 36) return xsdpError.InvalidSize;

    var sum: u8 = 0;
    for (xsdp_bytes[0..len]) |b| sum +%= b;
    if (sum != 0) return xsdpError.InvalidChecksum;
}

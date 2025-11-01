//! ACPI XSDP (RSDP) validation utilities.
//!
//! Provides a helper to validate the Extended System Description Pointer
//! structure retrieved from firmware. Ensures the signature matches, length
//! is sane, and the checksum is correct before ACPI tables are accessed.

const paging = @import("paging.zig");
const serial = @import("serial.zig");
const std = @import("std");

const VAddr = paging.VAddr;

/// Errors that may occur while validating the XSDP.
const xsdpError = error{
    InvalidSignature,
    InvalidSize,
    InvalidChecksum,
};

/// Validates the ACPI XSDP (RSDP) structure at the provided virtual address.
///
/// Performs three checks:
/// 1. Signature matches `"RSD PTR "`
/// 2. Reported structure length is at least 36 bytes
/// 3. Entire structure checksum modulo 256 is zero
///
/// Arguments:
/// - `xsdp_virt`: virtual address where the XSDP/RSDP resides (physmap).
///
/// Returns:
/// - `void` on success.
/// - `xsdpError.InvalidSignature` if the signature does not match.
/// - `xsdpError.InvalidSize` if the structure length is too small.
/// - `xsdpError.InvalidChecksum` if the checksum does not validate.
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

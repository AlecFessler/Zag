//! ACPI tables and helpers for XSDP/XSDT/MADT/HPET.
//!
//! Provides packed type definitions for key ACPI structures used during early
//! kernel bring-up and hardware discovery, plus helpers to validate checksums
//! and iterate table entries. These utilities are intentionally minimal and
//! freestanding so they can be used before the heap is online.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `MadtType` – enumeration of MADT entry kinds.
//! - `AnyMadt` – tagged union over all supported MADT entry payloads.
//! - `GenericAddressStruct` – ACPI GAS address descriptor.
//! - `HpetTable` – HPET ACPI table with helpers.
//! - `IoApic` – MADT I/O APIC entry payload.
//! - `IntSrcOverride` – MADT interrupt source override entry payload.
//! - `LapicAddrOverride` – MADT local APIC address override entry payload.
//! - `LocalApic` – MADT local APIC entry payload.
//! - `Madt` – Multiple APIC Description Table with iterator over entries.
//! - `Sdt` – Generic ACPI System Description Table header.
//! - `Xsdp` – ACPI RSDP/XSDP structure with validation helpers.
//! - `Xsdt` – Extended System Description Table with iterator over entries.
//!
//! ## Constants
//! - `validationError` – error set for ACPI validation failures.
//! - `VAddr` – alias to the architecture’s virtual address wrapper.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `HpetTable.fromVAddr` – view a `VAddr` as a `*HpetTable`.
//! - `HpetTable.validate` – verify HPET signature/checksum/GAS sanity.
//! - `Madt.fromVAddr` – view a `VAddr` as a `*Madt`.
//! - `Madt.validate` – verify MADT signature and checksum.
//! - `Madt.iter` – create an iterator over variable-length MADT entries.
//! - `Madt.Iterator.init` – construct a MADT iterator.
//! - `Madt.Iterator.next` – fetch the next MADT entry slice.
//! - `Madt.asBytes` – view the MADT as a byte slice (private).
//! - `Sdt.fromVAddr` – view a `VAddr` as a `*const Sdt`.
//! - `Xsdp.fromVAddr` – view a `VAddr` as a `*Xsdp`.
//! - `Xsdp.validate` – verify XSDP signature/size/checksums.
//! - `Xsdp.asBytes` – view the XSDP as a byte slice (private).
//! - `Xsdt.fromVAddr` – view a `VAddr` as a `*Xsdt`.
//! - `Xsdt.validate` – verify XSDT signature/checksum.
//! - `Xsdt.iter` – create an iterator over u64 SDT pointers.
//! - `Xsdt.Iterator.init` – construct an XSDT iterator.
//! - `Xsdt.Iterator.next` – fetch next u64 physical address entry.
//! - `Xsdt.asBytes` – view the XSDT as a byte slice (private).
//! - `decodeMadt` – decode a raw MADT entry into a typed `AnyMadt`.

const paging = @import("paging.zig");
const serial = @import("serial.zig");
const std = @import("std");

/// Alias for the architecture’s virtual address wrapper type.
const VAddr = paging.VAddr;

/// Error set for ACPI structure validation failures.
const validationError = error{
    InvalidSignature,
    InvalidSize,
    InvalidChecksum,
};

/// MADT entry type identifiers as defined by the ACPI specification.
pub const MadtType = enum(u8) {
    local_apic = 0,
    ioapic = 1,
    int_src_override = 2,
    lapic_nmi = 4,
    lapic_addr_override = 5,
};

/// Tagged union that holds any supported MADT entry payload.
pub const AnyMadt = union(MadtType) {
    local_apic: LocalApic,
    ioapic: IoApic,
    int_src_override: IntSrcOverride,
    lapic_nmi: []const u8,
    lapic_addr_override: LapicAddrOverride,
};

/// Generic Address Structure (GAS) used by ACPI to describe MMIO/IO ports.
pub const GenericAddressStruct = packed struct {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
};

/// HPET ACPI table header and fields required for timer discovery.
pub const HpetTable = packed struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: u48,
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    event_timer_block_id: u32,
    base_address: GenericAddressStruct,
    hpet_number: u8,
    min_tick: u16,
    page_protection: u8,

    /// Summary:
    /// Interprets a virtual address as a `*HpetTable` without copying.
    ///
    /// Arguments:
    /// - `v`: Virtual address pointing to the start of an HPET table.
    ///
    /// Returns:
    /// - `*HpetTable` pointing to the same memory.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn fromVAddr(v: VAddr) *HpetTable {
        @setRuntimeSafety(false);
        return @ptrFromInt(v.addr);
    }

    /// Summary:
    /// Validates the HPET table’s signature, checksum, and that the GAS refers
    /// to system memory.
    ///
    /// Arguments:
    /// - `self`: Table to validate.
    ///
    /// Returns:
    /// - `!void` on success; error on failure.
    ///
    /// Errors:
    /// - `validationError.InvalidSignature` if signature is not `"HPET"`.
    /// - `validationError.InvalidChecksum` if table checksum is non-zero.
    /// - `validationError.InvalidSize` if the base address is not system memory.
    ///
    /// Panics:
    /// - None.
    pub fn validate(self: *const HpetTable) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "HPET")) {
            return validationError.InvalidSignature;
        }
        var sum: u8 = 0;
        const bytes = @as([*]const u8, @ptrCast(self))[0..self.length];
        for (bytes) |b| {
            sum +%= b;
        }
        if (sum != 0) {
            return validationError.InvalidChecksum;
        }
        if (self.base_address.address_space_id != 0) {
            return validationError.InvalidSize;
        }
    }
};

/// MADT I/O APIC entry payload describing an IOAPIC and its GSI base.
pub const IoApic = packed struct {
    ioapic_id: u8,
    _rsvd: u8 = 0,
    ioapic_addr: u32,
    gsi_base: u32,
};

/// MADT interrupt source override mapping legacy IRQs to GSIs.
pub const IntSrcOverride = packed struct {
    bus: u8,
    src: u8,
    gsi: u32,
    flags: u16,
};

/// MADT entry to override the physical address of the local APIC.
pub const LapicAddrOverride = packed struct {
    _rsvd: u16 = 0,
    addr: u64,
};

/// MADT local APIC entry payload describing a processor’s LAPIC ID and flags.
pub const LocalApic = packed struct {
    processor_uid: u8,
    apic_id: u8,
    flags: u32,
};

/// Multiple APIC Description Table used to enumerate LAPIC/IOAPIC topology.
pub const Madt = packed struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: u48,
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
    lapic_addr: u32,
    flags: u32,

    /// Summary:
    /// Interprets a virtual address as a `*Madt` without copying.
    ///
    /// Arguments:
    /// - `madt_virt`: Virtual address pointing to the start of a MADT.
    ///
    /// Returns:
    /// - `*Madt` pointing to the same memory.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn fromVAddr(madt_virt: VAddr) *Madt {
        @setRuntimeSafety(false);
        return @ptrFromInt(madt_virt.addr);
    }

    /// Summary:
    /// Validates the MADT’s signature and checksum.
    ///
    /// Arguments:
    /// - `self`: Table to validate.
    ///
    /// Returns:
    /// - `!void` on success; error on failure.
    ///
    /// Errors:
    /// - `validationError.InvalidSignature` if signature is not `"APIC"`.
    /// - `validationError.InvalidChecksum` if table checksum is non-zero.
    ///
    /// Panics:
    /// - None.
    pub fn validate(self: *const Madt) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "APIC")) {
            return validationError.InvalidSignature;
        }

        var sum: u8 = 0;
        for (self.asBytes(self.length)) |b| {
            sum +%= b;
        }
        if (sum != 0) {
            return validationError.InvalidChecksum;
        }
    }

    /// Header shared by all variable-length MADT entries.
    pub const EntryHeader = packed struct {
        /// Entry kind value (matches `MadtType`).
        kind: u8,
        /// Total byte length for this entry.
        length: u8,
    };

    /// View of a single MADT entry: header plus raw bytes slice.
    pub const Entry = struct {
        /// Parsed entry header.
        header: EntryHeader,
        /// Underlying bytes covering this entry (including header).
        bytes: []const u8,
    };

    /// Forward iterator over MADT entries in the variable-length region.
    pub const Iterator = struct {
        /// Table being iterated.
        madt: *const Madt,
        /// Current byte offset into the MADT.
        off: u64,

        /// Summary:
        /// Constructs a new iterator starting after the fixed header.
        ///
        /// Arguments:
        /// - `m`: MADT to iterate.
        ///
        /// Returns:
        /// - `Iterator` positioned at the first entry.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn init(m: *const Madt) Iterator {
            return .{
                .madt = m,
                .off = 36 + 8,
            };
        }

        /// Summary:
        /// Returns the next MADT entry or `null` at end/invalid.
        ///
        /// Arguments:
        /// - `self`: Iterator state (advanced on success).
        ///
        /// Returns:
        /// - `?Entry` which is `null` on end or malformed entry.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn next(self: *Iterator) ?Entry {
            if (self.off >= self.madt.length) return null;
            const bytes = self.madt.asBytes(self.madt.length);
            const hdr: *align(1) const EntryHeader = @ptrCast(bytes.ptr + self.off);
            const start = self.off;
            const len = hdr.length;
            if (len < 2 or start + len > self.madt.length) return null;
            self.off += len;
            return .{
                .header = hdr.*,
                .bytes = bytes[start .. start + len],
            };
        }
    };

    /// Summary:
    /// Creates an iterator over this MADT’s entries.
    ///
    /// Arguments:
    /// - `self`: Table to iterate.
    ///
    /// Returns:
    /// - `Iterator` positioned at the first entry.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn iter(self: *const Madt) Iterator {
        return Iterator.init(self);
    }

    /// Summary:
    /// Returns a view of the first `n` bytes of the MADT.
    ///
    /// Arguments:
    /// - `self`: Table to view.
    /// - `n`: Number of bytes to expose.
    ///
    /// Returns:
    /// - `[]const u8` slice into the underlying table memory.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn asBytes(self: *const Madt, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
    }
};

/// Generic ACPI System Description Table header (used to identify SDTs).
pub const Sdt = packed struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: u48,
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,

    /// Summary:
    /// Interprets a virtual address as a `*const Sdt` without copying.
    ///
    /// Arguments:
    /// - `sdt_virt`: Virtual address pointing to an SDT header.
    ///
    /// Returns:
    /// - `*const Sdt` pointing to the same memory.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn fromVAddr(sdt_virt: VAddr) *const Sdt {
        @setRuntimeSafety(false);
        return @ptrFromInt(sdt_virt.addr);
    }
};

/// ACPI RSDP/XSDP structure used to locate RSDT/XSDT and verify ACPI v2+.
pub const Xsdp = packed struct {
    signature: u64,
    checksum20: u8,
    oem_id: u48,
    revision: u8,
    rsdt_paddr: u32,
    length: u32,
    xsdt_paddr: u64,
    checksum_ext: u8,
    reserved: u24,

    /// Summary:
    /// Interprets a virtual address as a `*Xsdp` without copying.
    ///
    /// Arguments:
    /// - `xsdp_virt`: Virtual address pointing to the RSDP/XSDP.
    ///
    /// Returns:
    /// - `*Xsdp` pointing to the same memory.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn fromVAddr(xsdp_virt: VAddr) *Xsdp {
        @setRuntimeSafety(false);
        return @ptrFromInt(xsdp_virt.addr);
    }

    /// Summary:
    /// Validates signature, length, and checksums for ACPI v2+ XSDP.
    ///
    /// Arguments:
    /// - `self`: XSDP to validate.
    ///
    /// Returns:
    /// - `!void` on success; error on failure.
    ///
    /// Errors:
    /// - `validationError.InvalidSignature` if not `"RSD PTR "`.
    /// - `validationError.InvalidSize` if `length` is less than 36 bytes.
    /// - `validationError.InvalidChecksum` if either checksum is non-zero.
    ///
    /// Panics:
    /// - None.
    pub fn validate(self: *const Xsdp) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "RSD PTR ")) {
            return validationError.InvalidSignature;
        }

        if (self.length < 36) {
            return validationError.InvalidSize;
        }

        var sum: u8 = 0;
        for (self.asBytes(self.length)) |b| {
            sum +%= b;
        }
        if (sum != 0) {
            return validationError.InvalidChecksum;
        }
    }

    /// Summary:
    /// Returns a view of the first `n` bytes of the XSDP.
    ///
    /// Arguments:
    /// - `self`: XSDP to view.
    /// - `n`: Number of bytes to expose.
    ///
    /// Returns:
    /// - `[]const u8` slice into the underlying structure.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn asBytes(self: *const Xsdp, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
    }
};

/// Extended System Description Table holding u64 pointers to SDTs.
pub const Xsdt = packed struct {
    signature: u32,
    length: u32,
    revision: u8,
    checksum: u8,
    oem_id: u48,
    oem_table_id: u64,
    oem_revision: u32,
    creator_id: u32,
    creator_revision: u32,
    entries_base: u64,

    /// Summary:
    /// Interprets a virtual address as a `*Xsdt` without copying.
    ///
    /// Arguments:
    /// - `xsdt_virt`: Virtual address pointing to an XSDT.
    ///
    /// Returns:
    /// - `*Xsdt` pointing to the same memory.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn fromVAddr(xsdt_virt: VAddr) *Xsdt {
        @setRuntimeSafety(false);
        return @ptrFromInt(xsdt_virt.addr);
    }

    /// Summary:
    /// Validates the XSDT’s signature and checksum.
    ///
    /// Arguments:
    /// - `self`: XSDT to validate.
    ///
    /// Returns:
    /// - `!void` on success; error on failure.
    ///
    /// Errors:
    /// - `validationError.InvalidSignature` if signature is not `"XSDT"`.
    /// - `validationError.InvalidChecksum` if table checksum is non-zero.
    ///
    /// Panics:
    /// - None.
    pub fn validate(self: *const Xsdt) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "XSDT")) {
            return validationError.InvalidSignature;
        }

        var sum: u8 = 0;
        for (self.asBytes(self.length)) |b| sum +%= b;
        if (sum != 0) return validationError.InvalidChecksum;
    }

    /// Forward iterator that walks 64-bit physical pointers in the XSDT.
    pub const Iterator = struct {
        /// Table being iterated.
        xsdt: *const Xsdt,
        /// Current byte offset into the entries region.
        off: u64,

        /// Summary:
        /// Constructs a new iterator positioned at the first entry.
        ///
        /// Arguments:
        /// - `x`: XSDT to iterate.
        ///
        /// Returns:
        /// - `Iterator` positioned after the fixed header.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn init(x: *const Xsdt) Iterator {
            return .{
                .xsdt = x,
                .off = 36,
            };
        }

        /// Summary:
        /// Returns the next 64-bit physical address entry or `null`.
        ///
        /// Arguments:
        /// - `self`: Iterator state (advanced on success).
        ///
        /// Returns:
        /// - `?u64` next entry, or `null` if past the end.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn next(self: *Iterator) ?u64 {
            if (self.off + 8 > self.xsdt.length) return null;
            const bytes = self.xsdt.asBytes(self.xsdt.length);
            const paddr = std.mem.readInt(u64, @ptrCast(bytes.ptr + self.off), .little);
            self.off += 8;
            return paddr;
        }
    };

    /// Summary:
    /// Creates an iterator over the XSDT’s u64 pointer entries.
    ///
    /// Arguments:
    /// - `self`: Table to iterate.
    ///
    /// Returns:
    /// - `Iterator` positioned at the first entry.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    pub fn iter(self: *const Xsdt) Iterator {
        return Iterator.init(self);
    }

    /// Summary:
    /// Returns a view of the first `n` bytes of the XSDT.
    ///
    /// Arguments:
    /// - `self`: XSDT to view.
    /// - `n`: Number of bytes to expose.
    ///
    /// Returns:
    /// - `[]const u8` slice into the underlying table memory.
    ///
    /// Errors:
    /// - None.
    ///
    /// Panics:
    /// - None.
    fn asBytes(self: *const Xsdt, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
    }
};

/// Summary:
/// Decodes a single MADT `Entry` into a strongly-typed `AnyMadt` payload. This
/// is a zero-allocation transformation and assumes the caller has already
/// validated the containing MADT table.
///
/// Arguments:
/// - `e`: The MADT entry to decode. Must contain at least the two-byte header
///   plus the expected payload size for its entry type.
///
/// Returns:
/// - `AnyMadt` containing the decoded entry payload. For `.lapic_nmi`, the raw
///   entry byte slice is returned as-is.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn decodeMadt(e: Madt.Entry) AnyMadt {
    const p = e.bytes[2..];
    return switch (@as(MadtType, @enumFromInt(e.header.kind))) {
        .local_apic => .{
            .local_apic = .{
                .processor_uid = p[0],
                .apic_id = p[1],
                .flags = std.mem.readInt(u32, @ptrCast(p.ptr + 2), .little),
            },
        },
        .ioapic => .{
            .ioapic = .{
                .ioapic_id = p[0],
                .ioapic_addr = std.mem.readInt(u32, @ptrCast(p.ptr + 2), .little),
                .gsi_base = std.mem.readInt(u32, @ptrCast(p.ptr + 6), .little),
            },
        },
        .int_src_override => .{
            .int_src_override = .{
                .bus = p[0],
                .src = p[1],
                .gsi = std.mem.readInt(u32, @ptrCast(p.ptr + 2), .little),
                .flags = std.mem.readInt(u16, @ptrCast(p.ptr + 6), .little),
            },
        },
        .lapic_nmi => .{
            .lapic_nmi = e.bytes,
        },
        .lapic_addr_override => .{
            .lapic_addr_override = .{
                .addr = std.mem.readInt(u64, @ptrCast(p.ptr + 2), .little),
            },
        },
    };
}

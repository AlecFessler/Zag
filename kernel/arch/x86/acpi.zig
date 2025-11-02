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
const validationError = error{
    InvalidSignature,
    InvalidSize,
    InvalidChecksum,
};

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

    pub fn fromVAddr(xsdp_virt: VAddr) *Xsdp {
        @setRuntimeSafety(false);
        return @ptrFromInt(xsdp_virt.addr);
    }

    pub fn asBytes(self: *const Xsdp, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
    }

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
};

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

    pub fn fromVAddr(xsdt_virt: VAddr) *Xsdt {
        @setRuntimeSafety(false);
        return @ptrFromInt(xsdt_virt.addr);
    }

    pub fn validate(self: *const Xsdt) !void {
        if (!std.mem.eql(u8, @ptrCast(&self.signature), "XSDT")) {
            return validationError.InvalidSignature;
        }

        var sum: u8 = 0;
        for (self.asBytes(self.length)) |b| sum +%= b;
        if (sum != 0) return validationError.InvalidChecksum;
    }

    pub const Iterator = struct {
        xsdt: *const Xsdt,
        off: u64,

        pub fn init(x: *const Xsdt) Iterator {
            return .{
                .xsdt = x,
                .off = 36,
            };
        }

        pub fn next(self: *Iterator) ?u64 {
            if (self.off + 8 > self.xsdt.length) return null;
            const bytes = self.xsdt.asBytes(self.xsdt.length);
            const paddr = std.mem.readInt(u64, @ptrCast(bytes.ptr + self.off), .little);
            self.off += 8;
            return paddr;
        }
    };

    pub fn iter(self: *const Xsdt) Iterator {
        return Iterator.init(self);
    }

    fn asBytes(self: *const Xsdt, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
    }
};

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

    pub fn fromVAddr(sdt_virt: VAddr) *const Sdt {
        @setRuntimeSafety(false);
        return @ptrFromInt(sdt_virt.addr);
    }
};

pub const MadtType = enum(u8) {
    local_apic = 0,
    ioapic = 1,
    int_src_override = 2,
    lapic_nmi = 4,
    lapic_addr_override = 5,
};

pub const LocalApic = packed struct {
    processor_uid: u8,
    apic_id: u8,
    flags: u32,
};

pub const IoApic = packed struct {
    ioapic_id: u8,
    _rsvd: u8 = 0,
    ioapic_addr: u32,
    gsi_base: u32,
};

pub const IntSrcOverride = packed struct {
    bus: u8,
    src: u8,
    gsi: u32,
    flags: u16,
};

pub const LapicAddrOverride = packed struct {
    _rsvd: u16 = 0,
    addr: u64,
};

pub const AnyMadt = union(MadtType) {
    local_apic: LocalApic,
    ioapic: IoApic,
    int_src_override: IntSrcOverride,
    lapic_nmi: []const u8,
    lapic_addr_override: LapicAddrOverride,
};

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

    pub fn fromVAddr(madt_virt: VAddr) *Madt {
        @setRuntimeSafety(false);
        return @ptrFromInt(madt_virt.addr);
    }

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

    pub const EntryHeader = packed struct {
        kind: u8,
        length: u8,
    };

    pub const Entry = struct {
        header: EntryHeader,
        bytes: []const u8,
    };

    pub const Iterator = struct {
        madt: *const Madt,
        off: u64,

        pub fn init(m: *const Madt) Iterator {
            return .{
                .madt = m,
                .off = 36 + 8,
            };
        }

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

    pub fn iter(self: *const Madt) Iterator {
        return Iterator.init(self);
    }

    fn asBytes(self: *const Madt, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
    }
};

pub const GenericAddressStruct = packed struct {
    address_space_id: u8,
    register_bit_width: u8,
    register_bit_offset: u8,
    access_size: u8,
    address: u64,
};

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

    pub fn fromVAddr(v: VAddr) *HpetTable {
        @setRuntimeSafety(false);
        return @ptrFromInt(v.addr);
    }

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
            return error.InvalidSize;
        }
    }
};

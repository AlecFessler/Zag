const std = @import("std");
const zag = @import("zag");

const apic = zag.arch.x64.apic;
const arch = zag.arch.dispatch;
const cpu = zag.arch.x64.cpu;
const device_registry = zag.devices.registry;
const iommu = zag.arch.x64.iommu;
const memory_init = zag.memory.init;
const paging = zag.memory.paging;
const timers = zag.arch.x64.timers;

const DeviceClass = zag.memory.device_region.DeviceClass;
const MemoryPerms = zag.perms.memory.MemoryPerms;
const PAddr = zag.memory.address.PAddr;
const VAddr = zag.memory.address.VAddr;

const validationError = error{
    InvalidSignature,
    InvalidSize,
    InvalidChecksum,
};

pub const MadtType = enum(u8) {
    local_apic = 0,
    ioapic = 1,
    int_src_override = 2,
    lapic_nmi = 4,
    lapic_addr_override = 5,
};

pub const AnyMadt = union(MadtType) {
    local_apic: LocalApic,
    ioapic: IoApic,
    int_src_override: IntSrcOverride,
    lapic_nmi: []const u8,
    lapic_addr_override: LapicAddrOverride,
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
            return validationError.InvalidSize;
        }
    }
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

pub const LocalApic = packed struct {
    processor_uid: u8,
    apic_id: u8,
    flags: u32,
};

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

    fn asBytes(self: *const Xsdp, n: u64) []const u8 {
        const base: [*]const u8 = @ptrCast(self);
        return base[0..n];
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

pub fn parseAcpi(xsdp_phys: PAddr) !void {
    const xsdp_virt = VAddr.fromPAddr(xsdp_phys, null);
    const xsdp = Xsdp.fromVAddr(xsdp_virt);
    try xsdp.validate();

    const xsdt_phys = PAddr.fromInt(xsdp.xsdt_paddr);
    const xsdt_virt = VAddr.fromPAddr(xsdt_phys, null);
    const xsdt = Xsdt.fromVAddr(xsdt_virt);
    try xsdt.validate();

    var xsdt_iter = xsdt.iter();
    while (xsdt_iter.next()) |sdt_paddr| {
        const sdt_phys = PAddr.fromInt(sdt_paddr);
        const sdt_virt_x = VAddr.fromPAddr(sdt_phys, null);
        const sdt = Sdt.fromVAddr(sdt_virt_x);

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "APIC")) {
            const madt = Madt.fromVAddr(sdt_virt_x);
            try madt.validate();

            var lapic_base: u64 = @intCast(madt.lapic_addr);
            var madt_iter = madt.iter();
            var lapics_count: u32 = 0;
            while (madt_iter.next()) |e| {
                const entry = decodeMadt(e);
                switch (entry) {
                    .local_apic => |la| {
                        if (la.flags & 0x1 == 0) continue;
                        lapics_array[lapics_count] = la;
                        lapics_count += 1;
                    },
                    .ioapic => |_| {},
                    .int_src_override => |_| {},
                    .lapic_nmi => |_| {},
                    .lapic_addr_override => |x| {
                        lapic_base = x.addr;
                    },
                }
            }

            apic.lapics = lapics_array[0..lapics_count];

            const lapic_phys = PAddr.fromInt(std.mem.alignBackward(u64, lapic_base, paging.PAGE4K));
            const lapic_virt = VAddr.fromPAddr(lapic_phys, null);

            const mmio_perms: MemoryPerms = .{
                .write_perm = .write,
                .execute_perm = .no_execute,
                .cache_perm = .not_cacheable,
                .global_perm = .not_global,
                .privilege_perm = .kernel,
            };

            try arch.mapPage(
                memory_init.kernel_addr_space_root,
                lapic_phys,
                lapic_virt,
                mmio_perms,
            );

            apic.init(lapic_virt);
        }

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "HPET")) {
            const hpet_table = HpetTable.fromVAddr(sdt_virt_x);
            try hpet_table.validate();

            const hpet_phys = PAddr.fromInt(hpet_table.base_address.address);
            const hpet_virt = VAddr.fromPAddr(hpet_phys, null);

            const mmio_perms: MemoryPerms = .{
                .write_perm = .write,
                .execute_perm = .no_execute,
                .cache_perm = .not_cacheable,
                .global_perm = .not_global,
                .privilege_perm = .kernel,
            };

            try arch.mapPage(
                memory_init.kernel_addr_space_root,
                hpet_phys,
                hpet_virt,
                mmio_perms,
            );

            timers.hpet_timer = timers.Hpet.init(hpet_virt);
        }

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "MCFG")) {
            parseMcfg(sdt_virt_x, sdt.length) catch {};
        }

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "DMAR")) {
            parseDmar(sdt_virt_x, sdt.length) catch {};
        }

        if (std.mem.eql(u8, @ptrCast(&sdt.signature), "IVRS")) {
            parseIvrs(sdt_virt_x, sdt.length) catch {};
        }
    }

    if (device_registry.count() == 0) {
        enumeratePciLegacy();
    }

    probeSerialPorts();
    initIommuDevices();
}

const MMIO_PERMS: MemoryPerms = .{
    .write_perm = .write,
    .execute_perm = .no_execute,
    .cache_perm = .not_cacheable,
    .global_perm = .not_global,
    .privilege_perm = .kernel,
};

fn parseMcfg(mcfg_vaddr: VAddr, length: u32) !void {
    const header_size: u32 = 44;
    const entry_size: u32 = 16;
    if (length <= header_size) return;

    const num_entries = (length - header_size) / entry_size;
    var i: u32 = 0;
    while (i < num_entries) : (i += 1) {
        const entry_addr = mcfg_vaddr.addr + header_size + @as(u64, i) * entry_size;
        const bytes: [*]const u8 = @ptrFromInt(entry_addr);
        const base_address = std.mem.readInt(u64, bytes[0..8], .little);
        const start_bus = bytes[10];
        const end_bus = bytes[11];

        if (base_address == 0) continue;

        const ecam_phys = PAddr.fromInt(base_address);
        const ecam_size = (@as(u64, end_bus) - @as(u64, start_bus) + 1) << 20;

        var offset: u64 = 0;
        while (offset < ecam_size) : (offset += paging.PAGE4K) {
            const page_phys = PAddr.fromInt(base_address + offset);
            const page_virt = VAddr.fromPAddr(page_phys, null);
            arch.mapPage(memory_init.kernel_addr_space_root, page_phys, page_virt, MMIO_PERMS) catch continue;
        }

        enumeratePci(VAddr.fromPAddr(ecam_phys, null), start_bus, end_bus);
    }
}

fn pciConfigRead32(ecam_base: VAddr, bus: u8, dev: u5, func: u3, offset: u12) u32 {
    const addr = ecam_base.addr +
        (@as(u64, bus) << 20) |
        (@as(u64, dev) << 15) |
        (@as(u64, func) << 12) |
        @as(u64, offset);
    return @as(*const volatile u32, @ptrFromInt(addr)).*;
}

fn pciConfigWrite32(ecam_base: VAddr, bus: u8, dev: u5, func: u3, offset: u12, value: u32) void {
    const addr = ecam_base.addr +
        (@as(u64, bus) << 20) |
        (@as(u64, dev) << 15) |
        (@as(u64, func) << 12) |
        @as(u64, offset);
    @as(*volatile u32, @ptrFromInt(addr)).* = value;
}

fn pciEcamProbeBarSize(ecam_base: VAddr, bus: u8, dev: u5, func: u3, bar_offset: u12) u64 {
    const original = pciConfigRead32(ecam_base, bus, dev, func, bar_offset);
    pciConfigWrite32(ecam_base, bus, dev, func, bar_offset, 0xFFFFFFFF);
    const sized = pciConfigRead32(ecam_base, bus, dev, func, bar_offset);
    pciConfigWrite32(ecam_base, bus, dev, func, bar_offset, original);

    if (original & 1 != 0) {
        const mask = sized & 0xFFFC;
        if (mask == 0) return 0;
        return (~mask + 1) & 0xFFFF;
    } else {
        const mask = sized & 0xFFFFFFF0;
        if (mask == 0) return 0;
        return ~mask + 1;
    }
}

fn pciClassToDeviceClass(class: u8, subclass: u8) DeviceClass {
    return switch (class) {
        0x01 => .storage,
        0x02 => .network,
        0x03 => .display,
        0x0C => if (subclass == 0x03) .usb else .unknown,
        else => .unknown,
    };
}

fn enumeratePci(ecam_base: VAddr, start_bus: u8, end_bus: u8) void {
    var bus: u16 = start_bus;
    while (bus <= end_bus) : (bus += 1) {
        var dev: u8 = 0;
        while (dev < 32) : (dev += 1) {
            const vendor_device = pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), 0, 0);
            const vendor: u16 = @truncate(vendor_device);
            if (vendor == 0xFFFF) continue;

            const header_type = @as(u8, @truncate(pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), 0, 0x0C) >> 16));
            const max_func: u8 = if (header_type & 0x80 != 0) 8 else 1;

            var func: u8 = 0;
            while (func < max_func) : (func += 1) {
                const vd = pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), 0);
                const v: u16 = @truncate(vd);
                const d: u16 = @truncate(vd >> 16);
                if (v == 0xFFFF) continue;

                const class_reg = pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), 0x08);
                const class_code: u8 = @truncate(class_reg >> 24);
                const subclass: u8 = @truncate(class_reg >> 16);

                if (class_code == 0x06) continue;

                const device_class = pciClassToDeviceClass(class_code, subclass);

                if (header_type & 0x7F != 0) continue;

                var bar_idx: u12 = 0;
                while (bar_idx < 6) : (bar_idx += 1) {
                    const bar_offset: u12 = 0x10 + bar_idx * 4;
                    const bar_val = pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), bar_offset);

                    if (bar_val == 0) continue;

                    if (bar_val & 1 != 0) {
                        const port_base: u16 = @truncate(bar_val & 0xFFFC);
                        if (port_base == 0) continue;
                        const port_size = pciEcamProbeBarSize(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), bar_offset);
                        const port_count: u16 = if (port_size > 0) @truncate(port_size) else 32;
                        _ = device_registry.registerPortIoDevice(port_base, port_count, device_class, v, d, class_code, subclass, @intCast(bus), @intCast(dev), @intCast(func)) catch continue;
                    } else {
                        const bar_type = (bar_val >> 1) & 0x3;
                        var phys_addr: u64 = bar_val & 0xFFFFFFF0;

                        if (bar_type == 2 and bar_idx < 5) {
                            const bar_high = pciConfigRead32(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), bar_offset + 4);
                            phys_addr |= @as(u64, bar_high) << 32;
                            bar_idx += 1;
                        }

                        if (phys_addr == 0) continue;

                        const bar_size = pciEcamProbeBarSize(ecam_base, @intCast(bus), @intCast(dev), @intCast(func), bar_offset);
                        const aligned_size = if (bar_size >= paging.PAGE4K)
                            std.mem.alignForward(u64, bar_size, paging.PAGE4K)
                        else
                            paging.PAGE4K;

                        _ = device_registry.registerMmioDevice(
                            PAddr.fromInt(phys_addr),
                            aligned_size,
                            device_class,
                            v,
                            d,
                            class_code,
                            subclass,
                            @intCast(bus),
                            @intCast(dev),
                            @intCast(func),
                        ) catch continue;

                        // Only register the first MMIO BAR per PCI function.
                        break;
                    }
                }
            }
        }
    }
}

fn pciLegacyWrite32(bus: u8, dev: u5, func: u3, offset: u8, value: u32) void {
    const addr: u32 = 0x80000000 |
        (@as(u32, bus) << 16) |
        (@as(u32, dev) << 11) |
        (@as(u32, func) << 8) |
        (@as(u32, offset) & 0xFC);
    cpu.outd(addr, 0xCF8);
    cpu.outd(value, 0xCFC);
}

fn pciProbeBarSize(bus: u8, dev: u5, func: u3, bar_offset: u8) u64 {
    const original = pciLegacyRead32(bus, dev, func, bar_offset);
    pciLegacyWrite32(bus, dev, func, bar_offset, 0xFFFFFFFF);
    const sized = pciLegacyRead32(bus, dev, func, bar_offset);
    pciLegacyWrite32(bus, dev, func, bar_offset, original);

    if (original & 1 != 0) {
        const mask = sized & 0xFFFC;
        if (mask == 0) return 0;
        return (~mask + 1) & 0xFFFF;
    } else {
        const mask = sized & 0xFFFFFFF0;
        if (mask == 0) return 0;
        return ~mask + 1;
    }
}

fn pciLegacyRead32(bus: u8, dev: u5, func: u3, offset: u8) u32 {
    const addr: u32 = 0x80000000 |
        (@as(u32, bus) << 16) |
        (@as(u32, dev) << 11) |
        (@as(u32, func) << 8) |
        (@as(u32, offset) & 0xFC);
    cpu.outd(addr, 0xCF8);
    return cpu.ind(0xCFC);
}

fn enumeratePciLegacy() void {
    var bus: u16 = 0;
    while (bus < 256) : (bus += 1) {
        var dev: u8 = 0;
        while (dev < 32) : (dev += 1) {
            const vendor_device = pciLegacyRead32(@intCast(bus), @intCast(dev), 0, 0);
            const vendor: u16 = @truncate(vendor_device);
            if (vendor == 0xFFFF) continue;

            const header_type = @as(u8, @truncate(pciLegacyRead32(@intCast(bus), @intCast(dev), 0, 0x0C) >> 16));
            const max_func: u8 = if (header_type & 0x80 != 0) 8 else 1;

            var func: u8 = 0;
            while (func < max_func) : (func += 1) {
                const vd = pciLegacyRead32(@intCast(bus), @intCast(dev), @intCast(func), 0);
                const v: u16 = @truncate(vd);
                const d: u16 = @truncate(vd >> 16);
                if (v == 0xFFFF) continue;

                const class_reg = pciLegacyRead32(@intCast(bus), @intCast(dev), @intCast(func), 0x08);
                const class_code: u8 = @truncate(class_reg >> 24);
                const subclass: u8 = @truncate(class_reg >> 16);

                if (class_code == 0x06) continue;

                const device_class = pciClassToDeviceClass(class_code, subclass);

                if (header_type & 0x7F != 0) continue;

                var bar_idx: u8 = 0;
                while (bar_idx < 6) : (bar_idx += 1) {
                    const bar_offset: u8 = 0x10 + bar_idx * 4;
                    const bar_val = pciLegacyRead32(@intCast(bus), @intCast(dev), @intCast(func), bar_offset);

                    if (bar_val == 0) continue;

                    if (bar_val & 1 != 0) {
                        const port_base: u16 = @truncate(bar_val & 0xFFFC);
                        if (port_base == 0) continue;
                        const port_size = pciProbeBarSize(@intCast(bus), @intCast(dev), @intCast(func), bar_offset);
                        const port_count: u16 = if (port_size > 0) @truncate(port_size) else 32;
                        _ = device_registry.registerPortIoDevice(port_base, port_count, device_class, v, d, class_code, subclass, @intCast(bus), @intCast(dev), @intCast(func)) catch continue;
                    } else {
                        const phys_addr: u64 = bar_val & 0xFFFFFFF0;
                        if (phys_addr == 0) continue;
                        const bar_size = pciProbeBarSize(@intCast(bus), @intCast(dev), @intCast(func), bar_offset);
                        const aligned_size = if (bar_size >= paging.PAGE4K)
                            std.mem.alignForward(u64, bar_size, paging.PAGE4K)
                        else
                            paging.PAGE4K;

                        _ = device_registry.registerMmioDevice(
                            PAddr.fromInt(phys_addr),
                            aligned_size,
                            device_class,
                            v,
                            d,
                            class_code,
                            subclass,
                            @intCast(bus),
                            @intCast(dev),
                            @intCast(func),
                        ) catch continue;

                        // Only register the first MMIO BAR per PCI function.
                        break;
                    }
                }
            }
        }
    }
}

fn probeSerialPorts() void {
    const com_ports = [_]u16{ 0x3F8, 0x2F8, 0x3E8, 0x2E8 };
    for (com_ports) |port| {
        cpu.outb(0xA5, port + 7);
        const readback = cpu.inb(port + 7);
        if (readback == 0xA5) {
            cpu.outb(0x00, port + 7);
            _ = device_registry.registerPortIoDevice(port, 8, .serial, 0, 0, 0, 0, 0, 0, 0) catch continue;
        }
    }
}

fn parseDmar(dmar_vaddr: VAddr, length: u32) !void {
    const header_size: u32 = 48;
    if (length <= header_size) return;

    var offset: u32 = header_size;
    while (offset + 4 <= length) {
        const entry_type = @as(*const volatile u16, @ptrFromInt(dmar_vaddr.addr + offset)).*;
        const entry_len = @as(*const volatile u16, @ptrFromInt(dmar_vaddr.addr + offset + 2)).*;
        if (entry_len == 0) break;

        if (entry_type == 0 and entry_len >= 16) {
            const reg_base = @as(*const volatile u64, @ptrFromInt(dmar_vaddr.addr + offset + 8)).*;
            if (reg_base != 0) {
                iommu.initIntel(PAddr.fromInt(reg_base)) catch {};
                break;
            }
        }

        offset += entry_len;
    }
}

fn parseIvrs(ivrs_vaddr: VAddr, length: u32) !void {
    const header_size: u32 = 48;
    if (length <= header_size) return;

    var offset: u32 = header_size;
    while (offset + 4 <= length) {
        const entry_type = @as(*const volatile u8, @ptrFromInt(ivrs_vaddr.addr + offset)).*;
        const entry_len = @as(*const volatile u16, @ptrFromInt(ivrs_vaddr.addr + offset + 2)).*;
        if (entry_len == 0) break;

        if ((entry_type == 0x10 or entry_type == 0x11 or entry_type == 0x40) and entry_len >= 24) {
            const reg_base = @as(*const volatile u64, @ptrFromInt(ivrs_vaddr.addr + offset + 8)).*;
            if (reg_base != 0) {
                iommu.initAmd(PAddr.fromInt(reg_base)) catch {};
                break;
            }
        }

        offset += entry_len;
    }
}

fn initIommuDevices() void {
    if (!iommu.isAvailable()) return;

    var i: u32 = 0;
    while (i < device_registry.count()) : (i += 1) {
        if (device_registry.getDevice(i)) |device| {
            if (device.device_type == .mmio and (device.pci_bus != 0 or device.pci_dev != 0 or device.pci_func != 0)) {
                iommu.setupDevice(device) catch {};
            }
        }
    }

    // Translation enable is deferred to the first dma_map syscall.
    // Enabling now with empty page tables would fault any early device DMA.
}

const MAX_CORES = 64;
var lapics_array: [MAX_CORES]LocalApic = undefined;

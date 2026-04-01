/// HID Report Descriptor Parser
///
/// Parses USB HID report descriptors to determine device type and report layout.
/// Used to interpret reports in Report Protocol (not boot protocol).

pub const DeviceType = enum(u8) {
    unknown = 0,
    keyboard = 1,
    mouse = 2,
};

pub const ReportField = struct {
    bit_offset: u16 = 0,
    bit_size: u8 = 0,
    count: u8 = 0,
};

pub const ReportInfo = struct {
    device_type: DeviceType = .unknown,
    report_id: u8 = 0,
    total_bits: u16 = 0,

    // Keyboard
    modifiers: ReportField = .{},
    keys: ReportField = .{},

    // Mouse
    buttons: ReportField = .{},
    x: ReportField = .{},
    y: ReportField = .{},
    wheel: ReportField = .{},
};

const MAX_USAGES = 16;

pub fn parse(desc: [*]const u8, len: u16) ReportInfo {
    var info = ReportInfo{};
    var bit_offset: u16 = 0;

    // Global state
    var usage_page: u16 = 0;
    var report_size: u8 = 0;
    var report_count: u8 = 0;
    var active_report_id: u8 = 0;
    var found_fields = false;

    // Local state
    var usages: [MAX_USAGES]u16 = .{0} ** MAX_USAGES;
    var usage_count: u8 = 0;
    var usage_min: u16 = 0;
    var usage_max: u16 = 0;

    var i: u16 = 0;
    while (i < len) {
        const header = desc[i];
        if (header == 0xFE) break; // Long item — unsupported

        const size: u8 = switch (@as(u2, @truncate(header))) {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
        };
        const item_type: u2 = @truncate(header >> 2);
        const tag: u4 = @truncate(header >> 4);

        if (i + 1 + @as(u16, size) > len) break;

        var value: u32 = 0;
        if (size >= 1) value = desc[i + 1];
        if (size >= 2) value |= @as(u32, desc[i + 2]) << 8;
        if (size >= 4) {
            value |= @as(u32, desc[i + 3]) << 16;
            value |= @as(u32, desc[i + 4]) << 24;
        }

        switch (item_type) {
            // Main items
            0 => {
                switch (tag) {
                    // Input
                    8 => {
                        const is_constant = (value & 1) != 0;
                        const is_variable = (value & 2) != 0;

                        if (!is_constant) {
                            classifyField(&info, usage_page, &usages, usage_count, usage_min, usage_max, report_size, report_count, is_variable, bit_offset);
                        }
                        bit_offset += @as(u16, report_size) * @as(u16, report_count);
                        info.total_bits = bit_offset;
                        found_fields = hasUsefulFields(&info);
                    },
                    // Collection
                    10 => {
                        if (value == 0x01 and info.device_type == .unknown) {
                            if (usage_count > 0 and usage_page == 0x01) {
                                if (usages[0] == 0x06) info.device_type = .keyboard;
                                if (usages[0] == 0x02) info.device_type = .mouse;
                            }
                        }
                    },
                    else => {},
                }
                // Clear local state after main item
                usage_count = 0;
                usage_min = 0;
                usage_max = 0;
            },
            // Global items
            1 => {
                switch (tag) {
                    0 => usage_page = @truncate(value), // Usage Page
                    7 => report_size = @truncate(value), // Report Size
                    8 => { // Report ID
                        const new_id: u8 = @truncate(value);
                        if (found_fields and new_id != active_report_id) {
                            // We already parsed one report's fields — stop
                            return info;
                        }
                        active_report_id = new_id;
                        info.report_id = new_id;
                        bit_offset = 0;
                    },
                    9 => report_count = @truncate(value), // Report Count
                    else => {},
                }
            },
            // Local items
            2 => {
                switch (tag) {
                    0 => { // Usage
                        if (usage_count < MAX_USAGES) {
                            usages[usage_count] = @truncate(value);
                            usage_count += 1;
                        }
                    },
                    1 => usage_min = @truncate(value), // Usage Minimum
                    2 => usage_max = @truncate(value), // Usage Maximum
                    else => {},
                }
            },
            else => {},
        }

        i += 1 + @as(u16, size);
    }

    return info;
}

fn hasUsefulFields(info: *const ReportInfo) bool {
    return info.modifiers.count > 0 or info.keys.count > 0 or
        info.buttons.count > 0 or info.x.bit_size > 0 or info.y.bit_size > 0;
}

fn classifyField(info: *ReportInfo, usage_page: u16, usages: *const [MAX_USAGES]u16, usage_count: u8, usage_min: u16, usage_max: u16, report_size: u8, report_count: u8, is_variable: bool, bit_offset: u16) void {
    if (usage_page == 0x07) {
        // Keyboard/Keypad Usage Page
        if (is_variable and usage_min >= 0xE0 and usage_max <= 0xE7) {
            info.modifiers = .{ .bit_offset = bit_offset, .bit_size = report_size, .count = report_count };
        } else if (!is_variable and info.keys.count == 0) {
            // Array-type key codes
            info.keys = .{ .bit_offset = bit_offset, .bit_size = report_size, .count = report_count };
        }
    } else if (usage_page == 0x09) {
        // Button Usage Page
        if (info.buttons.count == 0) {
            info.buttons = .{ .bit_offset = bit_offset, .bit_size = report_size, .count = report_count };
        }
    } else if (usage_page == 0x01 and is_variable) {
        // Generic Desktop — match X, Y, Wheel
        var u_idx: u8 = 0;
        var field_bit = bit_offset;
        while (u_idx < report_count) : (u_idx += 1) {
            const usage: u16 = if (u_idx < usage_count) usages[u_idx] else if (usage_min > 0) usage_min + u_idx else 0;

            switch (usage) {
                0x30 => info.x = .{ .bit_offset = field_bit, .bit_size = report_size, .count = 1 },
                0x31 => info.y = .{ .bit_offset = field_bit, .bit_size = report_size, .count = 1 },
                0x38 => info.wheel = .{ .bit_offset = field_bit, .bit_size = report_size, .count = 1 },
                else => {},
            }
            field_bit += report_size;
        }
    }
}

/// Extract an unsigned value at a bit offset from a report.
pub fn extractU(report: [*]const u8, bit_offset: u16, bit_size: u8) u32 {
    if (bit_size == 0) return 0;
    var result: u32 = 0;
    var bit: u16 = 0;
    while (bit < bit_size) : (bit += 1) {
        const total_bit = bit_offset + bit;
        const byte_idx = total_bit / 8;
        const bit_idx: u3 = @truncate(total_bit % 8);
        if (report[byte_idx] & (@as(u8, 1) << bit_idx) != 0) {
            result |= @as(u32, 1) << @as(u5, @truncate(bit));
        }
    }
    return result;
}

/// Extract a signed value at a bit offset from a report.
pub fn extractI(report: [*]const u8, bit_offset: u16, bit_size: u8) i32 {
    if (bit_size == 0) return 0;
    const raw = extractU(report, bit_offset, bit_size);
    // Sign-extend
    if (bit_size < 32) {
        const sign_bit = @as(u32, 1) << @as(u5, @truncate(bit_size - 1));
        if (raw & sign_bit != 0) {
            const mask = (@as(u32, 1) << @as(u5, @truncate(bit_size))) -% 1;
            return @bitCast(raw | ~mask);
        }
    }
    return @bitCast(raw);
}


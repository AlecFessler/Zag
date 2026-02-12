const std = @import("std");
const uefi = std.os.uefi;

pub fn openFile(
    root: *uefi.protocol.File,
    comptime name: [:0]const u8,
) !*uefi.protocol.File {
    const file: *uefi.protocol.File = root.open(
        &toUCS2(name),
        .read,
        .{},
    ) catch {
        return error.aborted;
    };
    return file;
}

pub fn readFile(
    file: *uefi.protocol.File,
    boot_services: *uefi.tables.BootServices,
) ![]u8 {
    const Info = uefi.protocol.File.Info;

    const info_len = try file.getInfoSize(.file);

    const info_ptr = try boot_services.allocatePool(.loader_data, info_len);
    defer boot_services.freePool(@ptrCast(info_ptr)) catch {};

    const info_slice_raw = @as([*]u8, @ptrCast(info_ptr))[0..info_len];
    const info_slice: []align(@alignOf(Info.File)) u8 = @alignCast(info_slice_raw);

    const finfo = try file.getInfo(.file, info_slice);

    const file_size = std.math.cast(usize, finfo.file_size) orelse return error.OutOfMemory;

    // this is acpi reclaim memory so that the kernel will physmap it
    // but will not hand it to the buddy allocator as usable
    const data_ptr = try boot_services.allocatePool(.acpi_reclaim_memory, file_size);
    errdefer boot_services.freePool(@ptrCast(data_ptr)) catch {};

    var data = @as([*]u8, @ptrCast(data_ptr))[0..file_size];

    try file.setPosition(0);

    var off: usize = 0;
    while (off < data.len) {
        const n = try file.read(data[off..]);
        if (n == 0) break;
        off += n;
    }

    if (off != data.len) return error.UnexpectedEndOfFile;

    return data;
}

fn toUCS2(comptime str: [:0]const u8) [str.len * 2:0]u16 {
    var usc2: [str.len * 2:0]u16 = [_:0]u16{0} ** (str.len * 2);
    for (str, 0..) |char, i| {
        usc2[i] = char;
        usc2[i + 1] = 0;
    }
    return usc2;
}

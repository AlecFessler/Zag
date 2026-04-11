/// Disk loader — reads bzImage and initramfs from NVMe disk.
/// Disk layout (written by the build script):
///   Sector 0: header
///     [0..8]   magic "ZAGVMIMG"
///     [8..16]  bzimage_offset (bytes)
///     [16..24] bzimage_size (bytes)
///     [24..32] initramfs_offset (bytes)
///     [32..40] initramfs_size (bytes)
///   Sector 1+: bzImage data
///   After bzImage: initramfs data

const lib = @import("lib");

const log = @import("log.zig");
const mem = @import("mem.zig");
const nvme = @import("nvme.zig");
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

pub const DiskImage = struct {
    bzimage_offset: u64,
    bzimage_size: u64,
    initramfs_offset: u64,
    initramfs_size: u64,
};

var ctrl: nvme.Controller = nvme.Controller{};

/// Initialize the NVMe controller by finding it in the perm_view.
pub fn init(pv: u64) bool {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    // Scan for NVMe device: PCI class storage (0x01), subclass NVM (0x08)
    for (0..128) |i| {
        if (view[i].entry_type == perm_view.ENTRY_TYPE_EMPTY) continue;
        if (view[i].entry_type == perm_view.ENTRY_TYPE_DEVICE_REGION) {
            if (view[i].deviceClass() == @intFromEnum(perms.DeviceClass.storage) and
                view[i].pciSubclass() == 0x08)
            {
                log.print("disk: found NVMe controller\n");
                const err = ctrl.initFromHandle(view[i].handle, view[i].deviceSizeOrPortCount());
                if (err == .none) {
                    log.print("disk: NVMe initialized\n");
                    return true;
                }
                log.print("disk: NVMe init failed\n");
                return false;
            }
        }
    }
    log.print("disk: no NVMe controller found\n");
    return false;
}

/// Read the disk image header and return the layout info.
pub fn readHeader() ?DiskImage {
    // Read sector 0
    if (!ctrl.readSectors(1, 0, 1)) {
        log.print("disk: failed to read header sector\n");
        return null;
    }

    const buf = nvme.dataBuffer(&ctrl);
    // Check magic
    if (buf[0] != 'Z' or buf[1] != 'A' or buf[2] != 'G' or buf[3] != 'V' or
        buf[4] != 'M' or buf[5] != 'I' or buf[6] != 'M' or buf[7] != 'G')
    {
        log.print("disk: bad magic in header\n");
        return null;
    }

    const hdr = DiskImage{
        .bzimage_offset = readU64(buf, 8),
        .bzimage_size = readU64(buf, 16),
        .initramfs_offset = readU64(buf, 24),
        .initramfs_size = readU64(buf, 32),
    };

    log.print("disk: bzImage offset=");
    log.dec(hdr.bzimage_offset);
    log.print(" size=");
    log.dec(hdr.bzimage_size);
    log.print("\n");
    log.print("disk: initramfs offset=");
    log.dec(hdr.initramfs_offset);
    log.print(" size=");
    log.dec(hdr.initramfs_size);
    log.print("\n");

    return hdr;
}

/// Load data from disk into guest physical memory.
/// Reads sector-by-sector from the NVMe disk.
pub fn loadToGuest(disk_offset: u64, size: u64, guest_phys: u64) bool {
    const lba_size: u64 = if (ctrl.lba_size > 0) ctrl.lba_size else 512;
    var offset: u64 = 0;

    while (offset < size) {
        const lba = (disk_offset + offset) / lba_size;
        if (!ctrl.readSectors(1, lba, 1)) {
            log.print("disk: read failed at LBA ");
            log.dec(lba);
            log.print("\n");
            return false;
        }

        const buf = nvme.dataBuffer(&ctrl);
        const chunk = @min(lba_size, size - offset);
        mem.writeGuest(guest_phys + offset, buf[0..chunk]);
        offset += lba_size;

        // Progress indicator every 1MB
        if (offset % (1024 * 1024) == 0) {
            log.print(".");
        }
    }
    return true;
}

fn readU64(buf: [*]const u8, offset: usize) u64 {
    return @as(*const align(1) u64, @ptrCast(buf + offset)).*;
}

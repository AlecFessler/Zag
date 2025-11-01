//! UEFI memory map helper: capture and expose a stable snapshot.
//!
//! Provides a thin wrapper around `BootServices.GetMemoryMap` that allocates a
//! buffer, retrieves the map, and returns a compact struct (`MMap`) containing
//! the key, descriptor pointer, sizes, and computed descriptor count. Intended
//! for use just before `ExitBootServices`.

const std = @import("std");

const uefi = std.os.uefi;

/// Memory map snapshot returned by `getMmap`.
///
/// Fields:
/// - `key`: token required by `ExitBootServices`.
/// - `mmap`: pointer to the first `MemoryDescriptor` in the allocated buffer.
/// - `mmap_size`: total size in bytes of the descriptor buffer.
/// - `descriptor_size`: size in bytes of each descriptor from firmware.
/// - `num_descriptors`: number of descriptors, computed as `mmap_size / descriptor_size`.
pub const MMap = extern struct {
    key: uefi.tables.MemoryMapKey,
    mmap: [*]uefi.tables.MemoryDescriptor,
    mmap_size: u64,
    descriptor_size: u64,
    num_descriptors: u64,
};

const log = std.log.scoped(.mmap);

/// Retrieve the current UEFI memory map into a freshly allocated pool buffer.
///
/// Behavior:
/// - Calls `_getMemoryMap` to discover required size (expects `.buffer_too_small`).
/// - Adds slack for allocation side effects, allocates buffer from `.loader_data`.
/// - Calls `_getMemoryMap` again to populate the buffer.
/// - On success, returns `MMap` with a valid key and counts. On failure, logs and returns `null`.
///
/// Arguments:
/// - `boot_services`: UEFI Boot Services pointer.
///
/// Returns:
/// - `MMap` on success (non-owning view over the allocated buffer).
/// - `null` on error; details are logged here.
///
/// Notes:
/// - The returned buffer resides in UEFI pool memory and should remain valid
///   until `ExitBootServices`. If you reattempt `ExitBootServices`, you must
///   reacquire a fresh map and key.
pub fn getMmap(
    boot_services: *uefi.tables.BootServices,
) ?MMap {
    var mmap_size: u64 = 0;
    var mmap: ?[*]uefi.tables.MemoryDescriptor = null;
    var key: uefi.tables.MemoryMapKey = undefined;
    var descriptor_size: u64 = undefined;
    var descriptor_version: u32 = undefined;

    var status = boot_services._getMemoryMap(
        &mmap_size,
        null,
        &key,
        &descriptor_size,
        &descriptor_version,
    );
    if (status != .buffer_too_small) return null;

    mmap_size += 2 * descriptor_size;

    status = boot_services._allocatePool(
        .loader_data,
        mmap_size,
        @ptrCast(&mmap),
    );
    if (status != .success) return null;

    status = boot_services._getMemoryMap(
        &mmap_size,
        @ptrCast(mmap),
        &key,
        &descriptor_size,
        &descriptor_version,
    );
    switch (status) {
        .success => return MMap{
            .key = key,
            .mmap = mmap.?,
            .mmap_size = mmap_size,
            .descriptor_size = descriptor_size,
            .num_descriptors = @divExact(mmap_size, descriptor_size),
        },
        else => {
            log.err("Expected success from getMemoryMap but got {s}", .{
                @tagName(status),
            });
            return null;
        },
    }
}

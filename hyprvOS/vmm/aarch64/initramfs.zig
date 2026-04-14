//! Initramfs loader for the aarch64 guest.
//!
//! The arm64 Linux boot protocol (Documentation/arm64/booting.rst
//! §"Kernel image format") lets the bootloader hand off an initramfs
//! blob by writing `linux,initrd-start` / `linux,initrd-end` properties
//! into /chosen — the fdt.zig generator emits those properties from the
//! values returned here.
//!
//! For M7 we do not yet ship a packaged arm64 initramfs; the loader is a
//! stub that reserves an empty range. When assets become available this
//! module should:
//!   1. Copy the compressed cpio archive from its source (embedded asset,
//!      NFS, NVMe — whichever the router image ends up using) into guest
//!      RAM at `load_addr`.
//!   2. Return `{ start = load_addr, end = load_addr + size }`.
//!
//! Linux treats an empty initramfs range as "no initrd", which is fine
//! for the skeleton boot — the guest will simply fail to find /init and
//! panic, which is a more productive failure mode than a silent hang.

pub const Range = struct {
    start: u64,
    end: u64,
};

/// Load an initramfs into guest memory at `load_addr`. Returns the
/// resulting guest-physical range for the FDT generator. Until a real
/// asset is wired in we return an empty range that starts and ends at
/// `load_addr`.
///
/// TODO(m7.6): wire this to an arm64-native cpio blob once the build
/// system has one. The x64 hyprvOS path already demonstrates embedding
/// via `hyprvOS/assets/assets.zig`.
pub fn load(load_addr: u64) Range {
    return .{ .start = load_addr, .end = load_addr };
}

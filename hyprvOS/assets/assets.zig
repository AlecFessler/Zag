/// Embedded Linux assets for QEMU fallback when NVMe is unavailable.
pub const bzimage = @embedFile("bzImage");
pub const initramfs = @embedFile("initramfs.cpio.gz");

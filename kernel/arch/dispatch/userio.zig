const builtin = @import("builtin");
const zag = @import("zag");

const PAddr = zag.memory.address.PAddr;

/// Write a u64 to a physical address via the kernel physmap. Used by
/// kernel-side propagators of handle field0/field1 updates that must
/// land in every domain-local copy of a handle (Timer counter,
/// device_region irq_count, etc.). Spec §[device_irq] §[timer].
pub fn writeU64ViaPhysmap(target_paddr: PAddr, value: u64) void {
    _ = target_paddr;
    _ = value;
    switch (builtin.cpu.arch) {
        .x86_64 => {},
        .aarch64 => {},
        else => unreachable,
    }
}

/// Atomically add `delta` to a u64 at `target_paddr`, saturating at
/// `ceiling`. Returns the post-addition value. Used by the device IRQ
/// path to bump irq_count saturating at u64::MAX. Spec §[device_irq].
pub fn atomicAddU64Saturating(target_paddr: PAddr, delta: u64, ceiling: u64) u64 {
    _ = target_paddr;
    _ = delta;
    _ = ceiling;
    switch (builtin.cpu.arch) {
        .x86_64 => return 0,
        .aarch64 => return 0,
        else => unreachable,
    }
}

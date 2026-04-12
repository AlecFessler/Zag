const std = @import("std");
const zag = @import("zag");

const cpu = zag.arch.x64.cpu;

const E_OK: i64 = 0;
const E_NODEV: i64 = -13;

/// System-wide power actions.
/// Spec §2.19, §4.61.
pub const PowerAction = enum(u8) {
    shutdown = 0,
    reboot = 1,
    sleep = 2,
    hibernate = 3,
    screen_off = 4,
};

/// Per-CPU power actions.
/// Spec §2.19, §4.62.
pub const CpuPowerAction = enum(u8) {
    set_freq = 0,
    set_idle = 1,
};

/// Perform a system-wide power action.
/// Spec §4.61; systems.md §25.
pub fn powerAction(action: PowerAction) i64 {
    switch (action) {
        .shutdown => doShutdown(),
        .reboot => doReboot(),
        .sleep => return E_NODEV, // S3 requires ACPI FADT parsing; stub for now
        .hibernate => return E_NODEV, // S4 requires ACPI FADT parsing; stub for now
        .screen_off => {
            // DPMS off via VGA attribute controller.
            // Read port 0x3DA to reset the flip-flop, then write 0x00 to 0x3C0 to blank.
            _ = cpu.inb(0x3DA);
            cpu.outb(0x00, 0x3C0);
            return E_OK;
        },
    }
}

/// Perform a per-CPU power action.
/// Spec §4.62; systems.md §25.
pub fn cpuPowerAction(action: CpuPowerAction, value: u64) i64 {
    switch (action) {
        .set_freq => {
            // IA32_PERF_CTL MSR (0x199): bits 8-15 hold the P-state ratio.
            // We need CPUID to confirm P-state support; stub as E_NODEV for now.
            _ = value;
            return E_NODEV;
        },
        .set_idle => {
            // MWAIT C-state control. Requires CPUID leaf 5 check.
            _ = value;
            return E_NODEV;
        },
    }
}

/// ACPI S5 shutdown. Falls back to QEMU port 0x604.
/// Does not return.
fn doShutdown() noreturn {
    // Fallback: QEMU shutdown via debug exit port.
    cpu.outw(0x2000, 0x604);
    // If that didn't work, halt forever.
    while (true) cpu.halt();
}

/// Reboot via keyboard controller reset, then triple fault.
/// Does not return.
fn doReboot() noreturn {
    // Strategy 1: Keyboard controller reset — write 0xFE to port 0x64.
    cpu.outb(0xFE, 0x64);

    // Strategy 2: Triple fault — load zero-length IDT and trigger interrupt.
    asm volatile (
        \\lidt (%[zero])
        \\int $3
        :
        : [zero] "r" (@as(u64, 0)),
    );

    while (true) cpu.halt();
}

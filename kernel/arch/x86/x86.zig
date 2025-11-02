//! Internal x86 subsystem module index.
//!
//! These are re-exported by `zag`.
//! Higher-level code should import `zag` instead of importing `x86` directly.
//!
//! This file acts only as a namespace unification layer so that the rest of the
//! kernel refers to architecture components consistently through e.g. `zag.x86.Cpu`
//! or `zag.x86.Paging`, without each callsite needing to know paths.
//!
//! # Included Submodules
//!
//! - `acpi.zig`       – ACPI table discovery and parsing
//! - `apic.zig`       – Local APIC, x2APIC, and LAPIC timer control
//! - `cpu.zig`        – CPU identification, feature flags, fences, and MSR helpers
//! - `exceptions.zig` – Exception vectors and handlers
//! - `gdt.zig`        – Global Descriptor Table setup
//! - `idt.zig`        – Interrupt Descriptor Table setup
//! - `interrupts.zig` – Interrupt state, stubs, and dispatch
//! - `irq.zig`        – IRQ routing and IOAPIC interactions
//! - `paging.zig`     – Page table structures and VAddr/PAddr helpers
//! - `serial.zig`     – Serial I/O for debug logging
//! - `timers.zig`     – HPET, TSC, and scheduling timer interfaces

pub const Acpi = @import("acpi.zig");
pub const Apic = @import("apic.zig");
pub const Cpu = @import("cpu.zig");
pub const Exceptions = @import("exceptions.zig");
pub const Gdt = @import("gdt.zig");
pub const Idt = @import("idt.zig");
pub const Interrupts = @import("interrupts.zig");
pub const Irq = @import("irq.zig");
pub const Paging = @import("paging.zig");
pub const Serial = @import("serial.zig");
pub const Timers = @import("timers.zig");

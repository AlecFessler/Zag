//! x86 architecture module entry point.
//!
//! Provides a single import hub for all x86-specific subsystems used by the kernel,
//! including CPU setup, descriptor tables, interrupt handling, paging, and VGA I/O.
//!
//! This module exists to simplify higher-level imports such as `@import("x86")`,
//! exposing all key components under one unified namespace for clarity and consistency.

pub const Acpi = @import("acpi.zig");
pub const Cpu = @import("cpu.zig");
pub const Gdt = @import("gdt.zig");
pub const Idt = @import("idt.zig");
pub const Interrupts = @import("interrupts.zig");
pub const Irq = @import("irq.zig");
pub const Isr = @import("isr.zig");
pub const Paging = @import("paging.zig");
pub const Serial = @import("serial.zig");

//! x86 architecture module entry point.
//!
//! Provides a single import hub for all x86-specific subsystems used by the kernel,
//! including CPU setup, descriptor tables, interrupt handling, paging, and serial I/O.
//!
//! This module exists to simplify higher-level imports such as `@import("x86")`,
//! exposing all key components under one unified namespace for clarity and consistency.

pub const Acpi = @import("acpi.zig");
pub const Apic = @import("apic.zig");
pub const Cpu = @import("cpu.zig");
pub const Exceptions = @import("exceptions.zig");
pub const Gdt = @import("gdt.zig");
pub const Idt = @import("idt.zig");
pub const Interrupts = @import("interrupts.zig");
pub const Irq = @import("irq.zig");
pub const Timers = @import("timers.zig");
pub const Paging = @import("paging.zig");
pub const Serial = @import("serial.zig");

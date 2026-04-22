//! AArch64 KVM object layer index.
//!
//! Mirrors `kernel/arch/x64/kvm/kvm.zig`. The files in this directory
//! implement the cross-architecture-shaped "KVM object layer" — Vm,
//! VCpu, VmExitBox, etc. — on top of the architecture-specific primitive
//! layer in `arch/aarch64/vm.zig`.
//!
//! File breakdown (see each file's module-level doc comment for detail):
//!
//!   vm.zig            Vm object + vm_create / vm_guest_map / vm_sysreg_passthrough /
//!                     vm_intc_{assert,deassert}_irq syscall implementations.
//!
//!   vcpu.zig          VCpu object + vm_vcpu_{run,set_state,get_state,interrupt}
//!                     syscall implementations, plus the per-vCPU run loop
//!                     that drives `hyp.vmResume`.
//!
//!   exit_box.zig      Portable VmExitBox + vm_recv / vm_reply.
//!
//!   exit_handler.zig  Classifies raw `vm.VmExitInfo` into "handle inline"
//!                     vs "deliver to VMM" and routes the inline cases.
//!
//!   guest_memory.zig  Guest-physical tracking helpers; walks host vaddr
//!                     ranges and installs stage-2 mappings via
//!                     `stage2.mapGuestPage`.
//!
//!   vgic.zig          In-kernel vGIC (GICv3 virtual CPU interface + GICD/GICR
//!                     MMIO emulation). Replaces x64/kvm/lapic.zig +
//!                     x64/kvm/ioapic.zig.
//!
//! Any code that does not depend on a GIC or stage-2 detail should be
//! kept as similar to its x64 counterpart as possible so the two
//! implementations stay easy to diff.
pub const exit_box = @import("exit_box.zig");
pub const exit_handler = @import("exit_handler.zig");
pub const guest_memory = @import("guest_memory.zig");
pub const psci = @import("psci.zig");
pub const regs = @import("regs.zig");
pub const vcpu = @import("vcpu.zig");
pub const vgic = @import("vgic.zig");
pub const vm = @import("vm.zig");
pub const vmid = @import("vmid.zig");
pub const vtimer = @import("vtimer.zig");

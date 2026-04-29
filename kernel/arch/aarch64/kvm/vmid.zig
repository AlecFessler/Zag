//! aarch64 stage-2 VMID allocator.
//!
//! Reserved for the future VM/vCPU run loop — once world-switch entry
//! is wired up, allocate/refresh/release will be reinstated here.
//! See `kernel/arch/aarch64/kvm/vm.zig` Vm.vmid / vmid_generation.

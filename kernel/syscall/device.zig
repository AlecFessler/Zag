const std = @import("std");
const zag = @import("zag");

const arch = zag.arch.dispatch;
const errors = zag.syscall.errors;
const paging = zag.memory.paging;
const sched = zag.sched.scheduler;

const VAddr = zag.memory.address.VAddr;
const VmReservationRights = zag.perms.permissions.VmReservationRights;

const E_OK = errors.E_OK;
const E_BADCAP = errors.E_BADCAP;
const E_EXIST = errors.E_EXIST;
const E_INVAL = errors.E_INVAL;
const E_NOENT = errors.E_NOENT;
const E_NOMEM = errors.E_NOMEM;
const E_NORES = errors.E_NORES;
const E_PERM = errors.E_PERM;

pub fn sysMemMmioMap(device_handle: u64, vm_handle: u64, offset: u64) i64 {
    if (!std.mem.isAligned(offset, paging.PAGE4K)) return E_INVAL;

    const proc = sched.currentProc();

    const device_entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (device_entry.object != .device_region) return E_BADCAP;
    if (!device_entry.deviceRights().map) return E_PERM;

    const vm_entry = proc.getPermByHandle(vm_handle) orelse return E_BADCAP;
    if (vm_entry.object != .vm_reservation) return E_BADCAP;

    const vm_res = vm_entry.object.vm_reservation;
    if (!vm_res.max_rights.mmio) return E_PERM;
    if (!vm_res.max_rights.read and !vm_res.max_rights.write) return E_PERM;

    const device = device_entry.object.device_region;

    if (device.device_type == .port_io) {
        // Port I/O devices use virtual BAR — write_combining is invalid
        if (vm_res.max_rights.write_combining) return E_INVAL;

        const map_size = std.mem.alignForward(u64, device.access.port_io.port_count, paging.PAGE4K);
        const range_end = std.math.add(u64, offset, map_size) catch return E_INVAL;
        if (range_end > vm_res.original_size) return E_INVAL;

        proc.vmm.memVirtualBarMap(
            device_handle,
            vm_handle,
            vm_res.original_start,
            vm_res.original_size,
            offset,
            device,
            .{
                .read = vm_res.max_rights.read,
                .write = vm_res.max_rights.write,
                .execute = vm_res.max_rights.execute,
            },
        ) catch |e| return switch (e) {
            error.CommittedPages => E_EXIST,
            else => E_INVAL,
        };

        return E_OK;
    }

    // MMIO device path
    if (device.device_type != .mmio) return E_INVAL;

    const range_end = std.math.add(u64, offset, device.access.mmio.size) catch return E_INVAL;
    if (range_end > vm_res.original_size) return E_INVAL;

    proc.vmm.memMmioMap(
        device_handle,
        vm_handle,
        vm_res.original_start,
        vm_res.original_size,
        offset,
        device,
        vm_res.max_rights.write_combining,
        .{
            .read = vm_res.max_rights.read,
            .write = vm_res.max_rights.write,
            .execute = vm_res.max_rights.execute,
        },
    ) catch |e| return switch (e) {
        error.CommittedPages => E_EXIST,
        else => E_INVAL,
    };

    return E_OK;
}

pub fn sysIrqAck(device_handle: u64) i64 {
    const proc = sched.currentProc();
    const entry = proc.getPermByHandle(device_handle) orelse return E_BADCAP;
    if (entry.object != .device_region) return E_BADCAP;
    if (!entry.deviceRights().irq) return E_PERM;

    // Look up the device's IRQ line, clear the pending bit, and unmask.
    const device = entry.object.device_region;
    const irq_line = arch.findIrqForDevice(device) orelse return E_INVAL;
    arch.clearIrqPendingBit(irq_line);
    arch.unmaskIrq(irq_line);
    return E_OK;
}

pub fn sysMemDmaMap(device_handle: u64, shm_handle: u64) i64 {
    const proc = sched.currentProc();

    // Both handle lookups and the shm refcount bump must happen under
    // perm_lock so a concurrent revoke_perm on the SHM handle cannot
    // decRef the SharedMemory between the lookup and arch.mapDmaPages.
    // Without this, the captured `*SharedMemory` becomes a UAF the
    // moment the racing revoke drops the last reference — mapDmaPages
    // then iterates a freed `shm.pages` slice. See exploits/dma_map_uaf.
    //
    // Lock ordering: perm_lock -> iommu locks is safe because no IOMMU
    // path reaches back into perm_lock.
    proc.perm_lock.lock();

    const dev_entry = proc.getPermByHandleLocked(device_handle) orelse {
        proc.perm_lock.unlock();
        return E_BADCAP;
    };
    if (dev_entry.object != .device_region) {
        proc.perm_lock.unlock();
        return E_BADCAP;
    }
    if (!dev_entry.deviceRights().dma) {
        proc.perm_lock.unlock();
        return E_PERM;
    }
    const device = dev_entry.object.device_region;
    if (device.device_type != .mmio) {
        proc.perm_lock.unlock();
        return E_INVAL;
    }

    const shm_entry = proc.getPermByHandleLocked(shm_handle) orelse {
        proc.perm_lock.unlock();
        return E_BADCAP;
    };
    if (shm_entry.object != .shared_memory) {
        proc.perm_lock.unlock();
        return E_BADCAP;
    }
    const shm = shm_entry.object.shared_memory;

    // Keep the SHM alive for the duration of this syscall regardless
    // of a concurrent revoke.
    shm.incRef();
    proc.perm_lock.unlock();

    if (!arch.isDmaRemapAvailable()) {
        shm.decRef();
        return E_NOMEM;
    }

    const dma_base = arch.mapDmaPages(device, shm) catch {
        shm.decRef();
        return E_NOMEM;
    };
    arch.enableDmaRemapping();
    proc.addDmaMapping(device, shm, dma_base, shm.num_pages) catch {
        arch.unmapDmaPages(device, dma_base, shm.num_pages);
        shm.decRef();
        return E_NORES;
    };
    shm.decRef();
    return @bitCast(dma_base);
}

pub fn sysMemDmaUnmap(device_handle: u64, shm_handle: u64) i64 {
    const proc = sched.currentProc();

    // Same perm_lock discipline as sysMemDmaMap. removeDmaMapping uses
    // `shm` only as a pointer-equality key, but a concurrent revoke +
    // slab reuse could hand out the same pointer to a different SHM
    // and falsely match an unrelated mapping. Look up + consume the
    // mapping with the SHM pinned by refcount.
    proc.perm_lock.lock();

    const dev_entry = proc.getPermByHandleLocked(device_handle) orelse {
        proc.perm_lock.unlock();
        return E_BADCAP;
    };
    if (dev_entry.object != .device_region) {
        proc.perm_lock.unlock();
        return E_BADCAP;
    }
    const device = dev_entry.object.device_region;

    const shm_entry = proc.getPermByHandleLocked(shm_handle) orelse {
        proc.perm_lock.unlock();
        return E_BADCAP;
    };
    if (shm_entry.object != .shared_memory) {
        proc.perm_lock.unlock();
        return E_BADCAP;
    }
    const shm = shm_entry.object.shared_memory;
    shm.incRef();
    proc.perm_lock.unlock();
    defer shm.decRef();

    if (!arch.isDmaRemapAvailable()) {
        // No IOMMU: no page table entries to clean up, just remove tracking
        _ = proc.removeDmaMapping(device, shm);
        return E_OK;
    }

    const mapping = proc.removeDmaMapping(device, shm) orelse return E_NOENT;
    arch.unmapDmaPages(device, mapping.dma_base, mapping.num_pages);
    return E_OK;
}

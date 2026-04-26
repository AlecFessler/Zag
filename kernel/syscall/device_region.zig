const zag = @import("zag");

const capability = zag.caps.capability;
const capability_domain = zag.capdom.capability_domain;
const device_region = zag.devices.device_region;
const errors = zag.syscall.errors;
const execution_context = zag.sched.execution_context;

const ErasedSlabRef = capability.ErasedSlabRef;
const ExecutionContext = execution_context.ExecutionContext;
const HandleType = capability.HandleType;
const RestartPolicy = capability.RestartPolicy;
const Word0 = capability.Word0;

const SELF_HANDLE_SLOT: u12 = 0;

/// dev_type field shape mirrors device_region handle field0 bits 0-3
/// (Spec §[device_region]). Anything outside the low nibble is an
/// invalid encoding for the discriminator vreg.
const DEV_TYPE_MASK: u64 = 0xF;
const DEV_TYPE_MMIO: u64 = 0;
const DEV_TYPE_PORT_IO: u64 = 1;

/// Mints a device_region handle backed by a kernel-side device record.
/// MMIO regions are described by `(base, size_or_count)` interpreted as
/// `(phys_base, byte_size)`; port_io regions interpret them as
/// `(base_port, port_count)` packed into the low 16 bits of each vreg
/// (Spec §[device_region] field0 layout).
///
/// `irq_source` is the platform IRQ line the kernel will route to this
/// region's `field1.irq_count` (Spec §[device_irq]); 0 means no IRQ
/// delivery, which leaves `field1.irq_count` pinned at 0 forever.
///
/// ```
/// request_device_region([1] dev_type, [2] base, [3] size_or_count, [4] irq_source) -> [1] handle
///
///   [1] dev_type: u64 packed as
///     bits  0-3: dev_type    — 0=mmio, 1=port_io
///     bits 4-63: _reserved
///
///   [2] base: u64
///     dev_type=mmio:    physical base address of the MMIO region
///     dev_type=port_io: base x86-64 I/O port (low 16 bits; bits 16-63 _reserved)
///
///   [3] size_or_count: u64
///     dev_type=mmio:    region size in bytes
///     dev_type=port_io: number of consecutive ports (low 16 bits; bits 16-63 _reserved)
///
///   [4] irq_source: u64
///     bits 0-31: platform IRQ source id (0 = no IRQ delivery)
///     bits 32-63: _reserved
/// ```
///
/// Returns the slot id of the minted device_region handle in the
/// caller's table, or a negative E_* code on failure. Returns E_FULL if
/// the caller's handle table has no free slot; E_NOMEM if the device
/// registry has no free slot.
pub fn requestDeviceRegion(
    caller: *anyopaque,
    dev_type: u64,
    base: u64,
    size_or_count: u64,
    irq_source: u64,
) i64 {
    if (dev_type & ~DEV_TYPE_MASK != 0) return errors.E_INVAL;
    if (irq_source & 0xFFFF_FFFF_0000_0000 != 0) return errors.E_INVAL;

    const ec: *ExecutionContext = @ptrCast(@alignCast(caller));
    const cd_ref = ec.domain;
    const cd = cd_ref.lock(@src()) catch return errors.E_BADCAP;

    // Self-handle slot 0 carries the calling domain's authority. A
    // domain that has been stripped of its self-handle (slot 0 cleared)
    // cannot request new device regions; this also rejects ABIs that
    // smuggle a non-self-handle into slot 0.
    const self_word0 = cd.user_table[SELF_HANDLE_SLOT].word0;
    if (Word0.reserved(self_word0) != 0) {
        cd_ref.unlock();
        return errors.E_INVAL;
    }
    const self_caps_word = Word0.caps(self_word0);
    if (self_caps_word == 0) {
        cd_ref.unlock();
        return errors.E_PERM;
    }

    const irq32: u32 = @truncate(irq_source);

    const dr_ref: ErasedSlabRef = blk: switch (dev_type) {
        DEV_TYPE_MMIO => {
            const r = device_region.registerMmio(base, size_or_count, irq32) catch {
                cd_ref.unlock();
                return errors.E_NOMEM;
            };
            break :blk r;
        },
        DEV_TYPE_PORT_IO => {
            if (base & 0xFFFF_FFFF_FFFF_0000 != 0) {
                cd_ref.unlock();
                return errors.E_INVAL;
            }
            if (size_or_count & 0xFFFF_FFFF_FFFF_0000 != 0) {
                cd_ref.unlock();
                return errors.E_INVAL;
            }
            const base16: u16 = @truncate(base);
            const count16: u16 = @truncate(size_or_count);
            const r = device_region.registerPortIo(base16, count16, irq32) catch {
                cd_ref.unlock();
                return errors.E_NOMEM;
            };
            break :blk r;
        },
        else => {
            cd_ref.unlock();
            return errors.E_INVAL;
        },
    };

    // field0 mirrors the spec §[device_region] handle layout: dev_type
    // in bits 0-3, base_port/port_count in bits 4-35 for port_io,
    // _reserved otherwise. field1 is the IRQ counter; a freshly minted
    // handle starts at 0 (Spec §[device_irq]).
    const field0: u64 = switch (dev_type) {
        DEV_TYPE_MMIO => DEV_TYPE_MMIO,
        DEV_TYPE_PORT_IO => blk: {
            const base16: u64 = base & 0xFFFF;
            const count16: u64 = size_or_count & 0xFFFF;
            break :blk DEV_TYPE_PORT_IO | (base16 << 4) | (count16 << 20);
        },
        else => unreachable,
    };
    const field1: u64 = 0;

    const slot = cd.mintHandle(
        HandleType.device_region,
        0,
        field0,
        field1,
        dr_ref,
        RestartPolicy.drop,
    ) catch {
        cd_ref.unlock();
        return errors.E_FULL;
    };
    cd_ref.unlock();

    return @intCast(slot);
}

# Bare Metal xHCI Diagnostic Decode

Last bare metal output with IOMMU enabled (before fixes):

## Controller 0 (1022:43f7 AMD Matisse USB 3.0)

```
init controller 0 (handle=0x5 mmio_size=0x8000)...
  FAILED: noop_timeout scratch=992 csz=32
  dma_size=0x408000
  usbcmd=0x5 usbsts=0x10
  dma_phys=0x1000 cmd_ring_phys=0x3e4000
  cmd_trb_ctrl=0x5c01 cycle=1
  evt_trb_ctrl=0x0 evt_cycle=0 expect=1
  erdp=0x3e4400 iman=0x2
  hccparams1=0x200ef81 pagesize=0x1 db_off=0x1800
  crcr_readback=0x8
```

| Field | Value | Bits | Meaning |
|---|---|---|---|
| `mmio_size` | `0x8000` | | 32KB PCI BAR size for MMIO registers |
| `scratch` | `992` | | **WRONG** hi/lo swapped. Should be ~31 after fix. Was `(31<<5)\|0` instead of `(0<<5)\|31` |
| `csz` | `32` | HCCPARAMS1 bit 2 = 0 | 32-byte context structures |
| `dma_size` | `0x408000` | | ~4MB, inflated by wrong scratchpad count. Should be ~200KB after fix |
| `usbcmd` | `0x5` | bit 0=1, bit 2=1 | RS=1 (Running), INTE=1 (Interrupts Enabled). Controller is running |
| `usbsts` | `0x10` | bit 4=1 | PCD (Port Change Detect) only. **No errors**: HCH=0 (not halted), HSE=0 (no bus error), HCE=0 |
| `dma_phys` | `0x1000` | | IOVA base from IOMMU. DMA address space starts here |
| `cmd_ring_phys` | `0x3e4000` | | IOVA of command ring. Deep into DMA region (after 992 scratchpad pages) |
| `cmd_trb_ctrl` | `0x5c01` | bits 15:10=0x17, bit 0=1 | TRB Type 23 = No Op Command, Cycle=1. **Correctly formatted** |
| `cycle` | `1` | | Current command ring cycle bit |
| `evt_trb_ctrl` | `0x0` | | Event ring dequeue position is **empty**. Controller never wrote a completion |
| `evt_cycle` | `0` | | Cycle bit at event ring dequeue = 0 |
| `expect` | `1` | | We expect cycle=1 for first event. Mismatch confirms no event written |
| `erdp` | `0x3e4400` | | Event Ring Dequeue Pointer IOVA. Right after command ring |
| `iman` | `0x2` | bit 1=1, bit 0=0 | IE=1 (Interrupt Enable), IP=0 (No Interrupt Pending). No interrupt generated |
| `hccparams1` | `0x200ef81` | see below | Capability parameters |
| `pagesize` | `0x1` | bit 0=1 | Page size = 2^(0+12) = 4096 bytes. Our hardcoded 4096 is correct |
| `db_off` | `0x1800` | | Doorbell array at mmio_base + 0x1800. Within 32KB BAR |
| `crcr_readback` | `0x8` | bit 3=1 | CRR=1 (Command Ring Running). Pointer undefined when CRR=1 per spec. **Not diagnostic** |

### HCCPARAMS1 decode (0x200ef81)

| Bits | Field | Value | Meaning |
|---|---|---|---|
| 0 | AC64 | 1 | 64-bit addressing capable |
| 1 | BNC | 0 | No bandwidth negotiation |
| 2 | CSZ | 0 | 32-byte context structures |
| 7:4 | IST | 0x8 | Isochronous Scheduling Threshold |
| 8 | PAE | 1 | Port Array Enhancement |
| 9 | SPC | 1 | Stopped Short Packet |
| 10 | SEC | 1 | Stopped EDTLA |
| 11 | CFC | 1 | Contiguous Frame ID |
| 15:12 | MaxPSASize | 0xE (14) | Max Primary Stream Array = 2^14 entries |
| 31:16 | xECP | 0x0200 | Extended capabilities at byte offset 0x800 (within 32KB BAR) |

### Analysis

Controller 0 is running with **no errors** from its perspective. But it **never processes the NOOP**:
- Event ring empty (evt_trb_ctrl=0, evt_cycle=0)
- No interrupt generated (iman IP=0)
- No HSE (bus error) reported

The controller either can't DMA-read the command ring at IOVA 0x3e4000, or can't DMA-write the completion event. Since there's no HSE, DMA isn't being actively rejected — it's **silently failing**. This matches: the IOMMU page tables are wrong, or the controller is behind an uninitialized second IOMMU, or COHERENT_EN is off causing stale page table walks.

---

## Controllers 1-3 (1022:15b6/15b7/15b8 AMD Promontory)

```
init controller 1 (handle=0x6 mmio_size=0x100000)...
  FAILED: noop_timeout scratch=64 csz=64
  dma_size=0x6a000
  usbcmd=0x4 usbsts=0x15
  dma_phys=0x1000 cmd_ring_phys=0x42000
  cmd_trb_ctrl=0x5c01 cycle=1
  evt_trb_ctrl=0x0 evt_cycle=0 expect=1
  erdp=0x42400 iman=0x2
  hccparams1=0x120ffc5 pagesize=0x1 db_off=0x2000
  crcr_readback=0x0
```

| Field | Value | Bits | Meaning |
|---|---|---|---|
| `mmio_size` | `0x100000` | | 1MB PCI BAR |
| `scratch` | `64` | | 64 scratchpad buffers (with old hi/lo swap; may change after fix) |
| `csz` | `64` | HCCPARAMS1 bit 2 = 1 | 64-byte context structures |
| `dma_size` | `0x6a000` | | ~424KB DMA region |
| `usbcmd` | `0x4` | bit 2=1, bit 0=0 | INTE=1 but **RS=0** (NOT running). Controller halted itself |
| `usbsts` | `0x15` (ctrl 1) | bits 0,2,4 | **HCH** (Halted) + **HSE** (Host System Error) + PCD |
| `usbsts` | `0x5` (ctrl 2,3) | bits 0,2 | **HCH** (Halted) + **HSE** (Host System Error) |
| `crcr_readback` | `0x0` | | Controller never accepted command ring pointer (halted before processing) |

### HCCPARAMS1 decode (0x120ffc5) — Controllers 1 & 2

| Bits | Field | Value | Meaning |
|---|---|---|---|
| 0 | AC64 | 1 | 64-bit addressing capable |
| 2 | CSZ | 1 | 64-byte context structures |
| 31:16 | xECP | 0x120F | Extended capabilities at byte offset 0x483C (within 1MB BAR) |

### HCCPARAMS1 decode (0x110ffc5) — Controller 3

| Bits | Field | Value | Meaning |
|---|---|---|---|
| 31:16 | xECP | 0x110F | Extended capabilities at byte offset 0x443C (within 1MB BAR) |

### Analysis

HSE = the IOMMU **actively rejected** their DMA transactions. The controller tried to access memory, got a bus error back, set HSE, and halted. These Promontory controllers sit behind a PCIe-to-PCI bridge — their DMA appears under the bridge's BDF, not their own. The IOMMU device table entry was at the controller's BDF, but the IOMMU looked up the bridge's BDF and found nothing.

---

## USBSTS Bit Reference

| Bit | Name | Meaning |
|---|---|---|
| 0 | HCH | HC Halted — controller is not running |
| 2 | HSE | Host System Error — DMA bus error (IOMMU rejected) |
| 3 | EINT | Event Interrupt pending |
| 4 | PCD | Port Change Detect — a port status changed |
| 8 | SSS | Save State Status |
| 9 | RSS | Restore State Status |
| 10 | SRE | Save/Restore Error |
| 11 | CNR | Controller Not Ready |
| 12 | HCE | Host Controller Error (internal) |

## USBCMD Bit Reference

| Bit | Name | Meaning |
|---|---|---|
| 0 | RS | Run/Stop — 1=running, 0=stopped |
| 1 | HCRST | Host Controller Reset |
| 2 | INTE | Interrupter Enable |
| 3 | HSEE | Host System Error Enable |
| 7 | LHCRST | Light HC Reset |

---

## What Our Fixes Should Change

| Fix | Effect |
|---|---|
| **Scratchpad hi/lo swap** | Controller 0: scratch 992→~31, DMA region ~4MB→~200KB, cmd_ring moves from IOVA 0x3e4000 to ~0x42000 |
| **BIOS handoff force-clear** | Controller 0 gets clean ownership even if BIOS is stubborn. SMI events cleared |
| **COHERENT_EN** | IOMMU snoops CPU caches during page table walks — no stale translations |
| **Default V=1/TV=1 DTEs** | All 65536 device table entries block DMA by default instead of potential passthrough |
| **Both BDF + alias DTEs** | Promontory controllers get entries at both their own BDF and the bridge's BDF |
| **Multi-IOMMU init** | All IOMMUs from IVRS initialized, not just the first one |
| **IVHD alias parsing** | Type 0x42/0x43 alias entries extracted and applied |
| **Contiguous SHM** | DMA shared memory allocated as contiguous physical block from buddy allocator |

# DesktopOS System Design

DesktopOS is a userspace desktop environment for the Zag microkernel. It introduces a two-level process hierarchy where middle-tier manager processes spawn and manage their own children.

---

## 1. Architecture

### 1.1 Process Hierarchy

```
root_service (broker, top-level)
├── device_manager (restartable, spawns drivers)
│   ├── serial_driver (restartable)
│   └── usb_driver (restartable — xHCI + USB enum + HID)
└── app_manager (restartable, spawns apps, sets policy)
    └── hello_app (NOT restartable)
```

Unlike routerOS's flat hierarchy (root + N children), desktopOS has two tiers:
- **Root** manages the two managers and brokers connections between them and their children.
- **Managers** each spawn and manage their own children using the same `proc_create` / `shm_create` / `grant_perm` syscalls that root uses.

### 1.2 Service IDs

Only system services get compile-time IDs. Apps do NOT have service IDs — app_manager tracks them internally using proc_handles.

```
DEVICE_MANAGER = 1
APP_MANAGER    = 2
SERIAL_DRIVER  = 3
USB_DRIVER     = 4
```

### 1.3 Process Rights

| Process | Rights |
|---------|--------|
| device_manager | grant_to, spawn_process, mem_reserve, device_own, restart, shm_create |
| app_manager | grant_to, spawn_process, mem_reserve, restart, shm_create |
| serial_driver | grant_to, mem_reserve, device_own, restart |
| usb_driver | grant_to, mem_reserve, device_own, restart |
| hello_app | grant_to, mem_reserve |

The `spawn_process` right is what enables the middle-tier managers to create child processes.

---

## 2. IPC Architecture

### 2.1 Command Channels (parent ↔ child)

Each parent creates a 4 KB SHM `CommandChannel` per child. The channel contains:
- Mutex and futex-based wake/reply flags
- Up to 8 `ConnectionEntry` slots, each with service_id, status, shm_handle, shm_size

The parent pre-populates entries with allowed service IDs. The child requests a connection by setting status to `requested` and waking the parent via futex. The parent (or broker) creates the SHM, fills in the handle, sets status to `connected`, and notifies the child.

### 2.2 Data Channel (app_manager ↔ device_manager)

Root brokers a bidirectional ring-buffer channel between app_manager and device_manager. This channel carries the driver availability protocol:

| Tag | Direction | Payload | Meaning |
|-----|-----------|---------|---------|
| `0x01` | DM → AM | `service_id: u32` | Driver available |
| `0x02` | AM → DM | `driver_service_id: u32` | Connect request |

### 2.3 App-to-Driver Channels

When an app needs a driver, root creates a data SHM and grants it to both managers. Each manager then grants it down to the appropriate child. The app opens as side A, the driver as side B.

---

## 3. Connection Brokering

### 3.1 Root's Routing Table

Root only knows its direct children. When app_manager requests a connection to `SERIAL_DRIVER`, root looks up the routing table to find which direct child manages that service:

```
SERIAL_DRIVER → DEVICE_MANAGER
```

Root creates the SHM, grants to both app_manager and device_manager, and writes connection entries to both command channels with service_id=SERIAL_DRIVER so they know which sub-service the SHM is for.

### 3.2 App Manager's Bucket Dispatch

App_manager maintains a queue (bucket) per driver service ID. When an app requests a driver:

1. App_manager pushes the app's proc_handle to that driver's bucket
2. App_manager requests the driver from root via its command channel
3. When root grants the SHM, app_manager pops the next proc_handle from the bucket
4. App_manager grants the SHM to that app and notifies it via its command channel

This supports multiple apps requesting the same driver — requests are fulfilled FIFO.

### 3.3 Device Manager's Direct Mapping

Device_manager maps driver service_id directly to child proc_handle (drivers are compile-time known). When it sees a new SHM granted by root with a matching service_id in its command channel, it grants it to the corresponding driver.

---

## 4. USB Driver

### 4.1 Architecture

The USB driver is monolithic: xHCI host controller, USB device enumeration, and HID report parsing all in one process. It communicates with apps via the standard data channel protocol, sending fixed 8-byte input event messages.

### 4.2 xHCI Initialization

1. Map MMIO BAR via `mmio_map` syscall
2. Enable PCI bus mastering via `pci_enable_bus_master`
3. Allocate DMA region (`shm_create` + `dma_map`) for TRB rings, device contexts, scratchpad
4. Read capability registers (CAPLENGTH, HCSPARAMS1/2, HCCPARAMS1, DBOFF, RTSOFF)
5. Reset controller (USBCMD.HCRST), wait for CNR=0
6. Set up DCBAA, command ring, event ring, ERST
7. Start controller (USBCMD.R/S=1)

### 4.3 Device Enumeration

Per connected port:
1. Detect device (PORTSC.CCS), reset port (PORTSC.PR), wait for PRC
2. Enable Slot command → get slot ID
3. Address Device command with input context (slot + EP0)
4. GET_DESCRIPTOR(device) and GET_DESCRIPTOR(configuration) control transfers
5. SET_CONFIGURATION to activate
6. Parse interface descriptors for HID class (0x03)
7. For boot protocol HID devices: SET_PROTOCOL(boot), SET_IDLE
8. Configure interrupt IN endpoints via Configure Endpoint command

### 4.4 HID Input Processing

- Keyboard boot reports: 8 bytes (modifier byte, reserved, 6 scancodes)
- Mouse boot reports: 3+ bytes (buttons, dx, dy as signed 8-bit)
- Driver tracks previous keyboard state to detect key press/release transitions
- Input events sent as 8-byte messages over data channel (see `libz/input.zig`)

### 4.5 DMA Memory

Uses the same pattern as routerOS NIC driver:
```
shm_create(size) → vm_reserve + shm_map → dma_map(device, shm) → physical base
```
Bump allocator within a 256 KB DMA region for all xHCI structures.

---

## 5. Boot Sequence

1. Root finds all device handles in perm_view
2. Root spawns device_manager with all device handles
3. Root spawns app_manager with no device handles
4. Root enters broker loop
5. Device_manager maps command channel, finds devices by class, spawns serial_driver and usb_driver
6. App_manager maps command channel, spawns hello_app
7. Both managers request connection to each other — root brokers a data channel
8. Device_manager sends DRIVER_AVAILABLE for each spawned driver to app_manager
9. Hello_app requests SERIAL_DRIVER and USB_DRIVER via its command channel to app_manager
10. App_manager pushes hello_app to SERIAL_DRIVER bucket, requests from root
11. Root creates SHM, grants to both managers
12. App_manager pops hello_app, grants SHM to it
13. Device_manager grants SHM to serial_driver
14. Hello_app opens channel side A, sends "Hello from desktopOS!\r\n"
15. Serial_driver receives message, writes to UART

### 5.1 Restart Recovery

On restart, managers detect `processRestartCount() > 0` in their perm_view slot 0. They then:
- Recover child process handles from existing ENTRY_TYPE_PROCESS entries
- Re-map existing SHM handles rather than waiting for new grants
- Re-request any connections that need re-establishment

---

## 6. Build System

### 6.1 Nested Embedding

The build uses three levels of ELF embedding:

```
serial_driver.elf ─┐
usb_driver.elf ────┤→ embedded in device_manager → device_manager.elf ─┐
                   │                                                    ├→ embedded in root → desktopOS.elf
hello_app.elf ─────→ embedded in app_manager ───→ app_manager.elf ─────┘
```

`desktopOS/build.zig` provides two helpers:
- `buildChild()` — leaf processes (no embedded children)
- `buildManagerChild()` — manager processes that embed their children via `embedded_children` module

### 6.2 Directory Structure

```
desktopOS/
  build.zig
  linker.ld
  libz/                  — local copy of userspace library (includes input.zig for HID events)
  root_service/main.zig
  device_manager/main.zig
  app_manager/main.zig
  serial_driver/main.zig
  usb_driver/main.zig
  hello_app/main.zig
  display.zig            — framebuffer rendering (future use)
  font8x16.zig           — VGA bitmap font (future use)
```

### 6.3 Build Commands

```bash
# Build desktopOS userspace
cd desktopOS && zig build

# Build kernel with desktopOS profile
zig build -Dprofile=desktop

# Run in QEMU
zig build run -Dprofile=desktop -Ddisplay none
```

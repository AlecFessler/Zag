# DesktopOS System Design

DesktopOS is a userspace desktop environment for the Zag microkernel. It introduces a two-level process hierarchy where middle-tier manager processes spawn and manage their own children.

---

## 1. Architecture

### 1.1 Process Hierarchy

```
root_service (broker, top-level)
├── device_manager (restartable, spawns drivers)
│   ├── serial_driver (restartable)
│   ├── usb_driver (restartable — xHCI + USB enum + HID)
│   └── compositor (restartable — GOP framebuffer + compositing + cursor)
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
COMPOSITOR     = 5
```

### 1.3 Process Rights

| Process | Rights |
|---------|--------|
| device_manager | grant_to, spawn_process, mem_reserve, device_own, restart, shm_create |
| app_manager | grant_to, spawn_process, mem_reserve, restart, shm_create |
| serial_driver | grant_to, mem_reserve, device_own, restart |
| usb_driver | grant_to, mem_reserve, device_own, restart, shm_create |
| compositor | grant_to, mem_reserve, device_own, restart, shm_create |
| hello_app | grant_to, mem_reserve |

The `spawn_process` right is what enables the middle-tier managers to create child processes.

---

## 2. IPC Architecture

### 2.1 Command Channels (parent <-> child)

Each parent creates a 4 KB SHM `CommandChannel` per child. The channel contains:
- Mutex and futex-based wake/reply flags
- Up to 8 `ConnectionEntry` slots, each with service_id, status, shm_handle, shm_size
- `active_app_index` and `active_app_gen` fields for relaying active app state from device_manager to drivers

The parent pre-populates entries with allowed service IDs. The child requests a connection by setting status to `requested` and waking the parent via futex. The parent (or broker) creates the SHM, fills in the handle, sets status to `connected`, and notifies the child.

### 2.2 Data Channel (app_manager <-> device_manager)

Root brokers a bidirectional ring-buffer channel between app_manager and device_manager. This channel carries:

| Tag | Direction | Payload | Meaning |
|-----|-----------|---------|---------|
| `0x01` | DM -> AM | `service_id: u32` | Driver available |
| `0x02` | AM -> DM | `driver_service_id: u32` | Connect request |
| `0x03` | DM -> AM | (none) | Subscribe to active app changes |
| `0x04` | AM -> DM | `app_index: u8` | Active app changed |
| `0x05` | DM -> AM | `app_index: u8` | Mouse click on window (active app change request) |

### 2.3 App-to-Driver Channels

When an app needs a driver, root creates a data SHM and grants it to both managers. Each manager then grants it down to the appropriate child. The app opens as side A, the driver as side B.

### 2.4 Framebuffer Channels (app <-> compositor)

For compositor connections, root creates a **4 MB SHM** instead of the standard 16 KB. This SHM is NOT a ring buffer — it has a custom layout:

```
Offset 0: FramebufferHeader (4096 bytes, page-aligned)
  - magic: u32 (0x5A414746 = "ZAGF")
  - width, height, stride: u32 (display dimensions)
  - format: u32 (0=BGR8, 1=RGB8)
  - frame_counter: u64 (atomic, incremented by app after writing pixels)
Offset 4096: Raw pixel data (BGRA, row-major, width*height*4 bytes)
```

Root skips `Channel.initAsSideA` for compositor SHMs. The compositor initializes the header with display dimensions; the app waits for magic before rendering.

### 2.5 Internal Mouse Channel (usb_driver <-> compositor)

Device_manager creates a 16 KB ring-buffer channel directly between usb_driver and compositor (both are its children). USB driver opens as side A, compositor as side B. Mouse events flow via `input.encodeMouse()` / `input.decodeMouse()`. The compositor applies deltas to track absolute cursor position.

---

## 3. Connection Brokering

### 3.1 Root's Routing Table

Root only knows its direct children. When app_manager requests a connection to a grandchild service, root looks up the routing table:

```
SERIAL_DRIVER -> DEVICE_MANAGER
USB_DRIVER    -> DEVICE_MANAGER
COMPOSITOR    -> DEVICE_MANAGER
```

Root creates the SHM (sized based on target: 4 MB for COMPOSITOR, 16 KB otherwise), grants to both managers, and writes connection entries to both command channels.

### 3.2 App Manager's Bucket Dispatch

App_manager maintains a queue (bucket) per driver service ID. When an app requests a driver:

1. App_manager pushes the app's proc_handle to that driver's bucket
2. App_manager requests the driver from root via its command channel
3. When root grants the SHM, app_manager pops the next proc_handle from the bucket
4. App_manager grants the SHM to that app and notifies it via its command channel

### 3.3 Device Manager's Direct Mapping

Device_manager maps driver service_id directly to child proc_handle. When it sees a new SHM granted by root with a matching service_id in its command channel, it grants it to the corresponding driver.

---

## 4. USB Driver

### 4.1 Architecture

The USB driver is monolithic: xHCI host controller, USB device enumeration, and HID report parsing all in one process. It communicates with apps via the standard data channel protocol, sending fixed 8-byte input event messages.

### 4.2 Multi-Channel Support

The USB driver manages multiple output channels:
- **Mouse channel**: Internal 16 KB ring buffer to compositor (mouse events always sent here)
- **App channels**: One per app that requests USB_DRIVER (keyboard to active only, mouse to active + compositor)
- Active app index is read from the command channel's `active_app_index` field, set by device_manager

### 4.3 xHCI Initialization

1. Map MMIO BAR via `mmio_map` syscall
2. Enable PCI bus mastering via `pci_enable_bus_master`
3. Allocate DMA region (`shm_create_with_rights` + `dma_map`) for TRB rings, device contexts, scratchpad
4. Read capability registers (CAPLENGTH, HCSPARAMS1/2, HCCPARAMS1, DBOFF, RTSOFF)
5. Reset controller (USBCMD.HCRST), wait for CNR=0
6. Set up DCBAA, command ring, event ring, ERST
7. Start controller (USBCMD.R/S=1)

### 4.4 Device Enumeration

Per connected port:
1. Detect device (PORTSC.CCS), reset port (PORTSC.PR), wait for PRC
2. Enable Slot command -> get slot ID
3. Address Device command with input context (slot + EP0)
4. GET_DESCRIPTOR(device) and GET_DESCRIPTOR(configuration) control transfers
5. SET_CONFIGURATION to activate
6. Parse interface descriptors for HID class (0x03)
7. For boot protocol HID devices: SET_PROTOCOL(boot), SET_IDLE
8. Configure interrupt IN endpoints via Configure Endpoint command

### 4.5 HID Input Processing

- Keyboard boot reports: 8 bytes (modifier byte, reserved, 6 scancodes)
- Mouse boot reports: 3+ bytes (buttons, dx, dy as signed 8-bit)
- Driver tracks previous keyboard state to detect key press/release transitions
- Input events sent as 8-byte messages over data channel (see `libz/input.zig`)

### 4.6 DMA Memory

```
shm_create_with_rights(size, rights) -> vm_reserve + shm_map -> dma_map(device, shm) -> physical base
```
Bump allocator within a 256 KB DMA region for all xHCI structures.

---

## 5. Compositor

### 5.1 Architecture

The compositor owns the GOP (Graphics Output Protocol) framebuffer. It receives app framebuffers via 4 MB SHM regions, composites them in draw order, and renders a mouse cursor on top.

### 5.2 Display Init

1. Find display device in perm_view (`DeviceClass.display`, `DeviceType.mmio`)
2. Read display dimensions from perm_view entry (fbWidth, fbHeight, fbStride, fbPixelFormat)
3. Map GOP framebuffer via `vm_reserve(.mmio = true)` + `mmio_map`
4. Fill with background color

### 5.3 Compositing Loop

Each frame:
1. Receive mouse events from internal channel, update cursor position (clamped to screen bounds)
2. Check for new 4 MB app framebuffer SHMs, initialize headers with display dimensions
3. Check each app's `frame_counter` for new frames
4. If any change: clear background, blit app framebuffers back-to-front, draw cursor
5. Yield between frames

### 5.4 Draw Order

Apps are composited in least-recently-active order:
- Least recently active drawn first (background)
- Most recently active (current active app) drawn last (foreground)
- Mouse cursor always on top

### 5.5 Active App Notification

Device_manager relays active app changes to the compositor via the command channel's `active_app_index` / `active_app_gen` fields. The compositor reads these to determine draw order.

---

## 6. Active App Model

### 6.1 Tracking

App_manager maintains `active_app_index` pointing to the currently active app in its `apps[]` array. When a new app is spawned, it automatically becomes the active app.

### 6.2 Subscription

Device_manager sends `SUBSCRIBE_ACTIVE_APP` (0x03) to app_manager over their data channel. App_manager responds immediately with the current active app and sends `ACTIVE_APP_CHANGED` (0x04) whenever the active app changes.

### 6.3 Relay to Drivers

Device_manager keeps mapped command channel pointers for each child driver. When it receives `ACTIVE_APP_CHANGED`, it writes `active_app_index` to each child's command channel and increments `active_app_gen` (waking via futex).

### 6.4 Input Routing

- Keyboard events: only sent to `app_channels[active_app_index]`
- Mouse events: sent to `app_channels[active_app_index]` AND `mouse_channel` (compositor always gets mouse)

---

## 7. Boot Sequence

1. Root finds all device handles in perm_view
2. Root spawns device_manager with all device handles
3. Root spawns app_manager with no device handles
4. Root enters broker loop
5. Device_manager maps command channel, finds devices by class, spawns serial_driver, usb_driver, and compositor
6. Device_manager creates internal mouse channel between usb_driver and compositor
7. App_manager maps command channel, spawns hello_app
8. Both managers request connection to each other -- root brokers a data channel
9. Device_manager sends DRIVER_AVAILABLE for each spawned driver to app_manager
10. Device_manager subscribes to active app changes
11. Hello_app requests SERIAL_DRIVER, COMPOSITOR, and USB_DRIVER via its command channel
12. App_manager pushes hello_app to each driver's bucket, requests from root
13. Root creates SHMs (16 KB for serial/USB, 4 MB for compositor), grants to both managers
14. App_manager pops hello_app, grants SHMs to it
15. Device_manager grants SHMs to serial_driver, usb_driver, compositor
16. Hello_app sends "Hello from desktopOS!" via serial, renders test pattern to compositor framebuffer
17. USB driver connects mouse channel to compositor and data channel to hello_app

### 7.1 Restart Recovery

On restart, managers detect `processRestartCount() > 0` in their perm_view slot 0. They then:
- Recover child process handles from existing ENTRY_TYPE_PROCESS entries
- Re-map existing SHM handles rather than waiting for new grants
- Re-request any connections that need re-establishment

---

## 8. Build System

### 8.1 Nested Embedding

The build uses three levels of ELF embedding:

```
serial_driver.elf -+
usb_driver.elf ----+-> embedded in device_manager -> device_manager.elf -+
compositor.elf ----+                                                     +-> embedded in root -> desktopOS.elf
                                                                         |
hello_app.elf -------> embedded in app_manager ----> app_manager.elf ----+
```

### 8.2 Directory Structure

```
desktopOS/
  build.zig
  linker.ld
  libz/                  -- local copy of userspace library
    channel.zig          -- ring-buffer data channels
    framebuffer.zig      -- framebuffer SHM protocol
    input.zig            -- HID input event protocol
    shm_protocol.zig     -- command channels and service IDs
  root_service/main.zig
  device_manager/main.zig
  app_manager/main.zig
  serial_driver/main.zig
  usb_driver/main.zig
  compositor/main.zig
  hello_app/main.zig
  display.zig            -- framebuffer rendering utilities (used for reference)
  font8x16.zig           -- VGA bitmap font
```

### 8.3 Build Commands

```bash
# Build desktopOS userspace
cd desktopOS && zig build

# Build kernel with desktopOS profile
zig build -Dprofile=desktop

# Run in QEMU (GTK display, KVM, IOMMU, USB devices)
zig build run -Dprofile=desktop

# Run without display (serial output only)
zig build run -Dprofile=desktop -Ddisplay none
```

# DesktopOS Specification

Observable behavior of Zag DesktopOS. This document describes what the desktop environment does from a user perspective, not how it is implemented internally (see [system.md](system.md) for that).

---

## 1. Overview

DesktopOS is a desktop-oriented userspace environment for the Zag microkernel. It uses a two-level process hierarchy with separate device management and application management services.

### Process topology

```
root_service
├── device_manager
│   ├── serial_driver
│   ├── usb_driver
│   └── compositor
└── app_manager
    └── hello_app
```

---

## 2. Process model

| Process | Role | Restartable |
|---------|------|-------------|
| root_service | Spawns managers, brokers IPC connections, monitors health | No (top-level) |
| device_manager | Manages device drivers, reports available drivers to app_manager | Yes |
| app_manager | Manages applications, enforces access policy, dispatches driver connections | Yes |
| serial_driver | UART 16550 I/O | Yes |
| usb_driver | xHCI host controller + USB enumeration + HID keyboard/mouse | Yes |
| compositor | GOP framebuffer owner, composites app framebuffers, draws cursor | Yes |
| hello_app | Renders framebuffer, receives USB input events, echoes to serial | No |

### Restartability

- device_manager and app_manager automatically restart on crash. On restart, they recover existing handles (device regions, SHM, child processes) from their permission view.
- Drivers are restartable by default.
- Apps are NOT restartable by default.

---

## 3. IPC channels

Processes communicate via shared memory channels brokered by parent processes:

- **Command channels**: Each parent creates a 4 KB SHM region for each child, used for connection management (requesting, granting).
- **Data channels**: 16 KB bidirectional ring buffers with CRC32 integrity, created on demand when two processes need to communicate.
- **Framebuffer channels**: 4 MB direct shared memory regions for compositor connections (no ring buffer — raw pixel data with an atomic frame counter).
- **Internal channels**: device_manager creates a 16 KB ring buffer between usb_driver and compositor for mouse events.

### Connection flow

When an app wants to use a device driver:

1. App requests the driver via its command channel to app_manager
2. App_manager checks policy (is this app allowed to use this driver?)
3. App_manager requests the connection from root
4. Root creates a shared memory region and grants it to both app_manager and device_manager
5. App_manager grants the SHM to the requesting app
6. Device_manager grants the SHM to the target driver
7. App and driver communicate directly through the shared channel

### Access policy

App_manager decides which apps can access which drivers. Each app's command channel is pre-populated with the driver service IDs it is allowed to connect to.

---

## 4. Device drivers

| Driver | Device | Status |
|--------|--------|--------|
| serial_driver | UART 16550 | Working |
| usb_driver | xHCI USB host controller (keyboard + mouse HID) | Working |
| compositor | GOP framebuffer (display output + mouse cursor) | Working |

Root passes all device handles to device_manager. Device_manager decides which drivers to spawn based on device class (serial, usb, display).

---

## 5. Input events

The USB driver sends fixed 8-byte input event messages to apps over data channels:

### Keyboard event (tag 0x01)

| Byte | Field |
|------|-------|
| 0 | Tag (0x01) |
| 1 | USB HID scancode |
| 2 | State (0=released, 1=pressed) |
| 3 | Modifier bitmap (LCtrl, LShift, LAlt, LGui, RCtrl, RShift, RAlt, RGui) |
| 4-7 | Reserved |

### Mouse event (tag 0x02)

| Byte | Field |
|------|-------|
| 0 | Tag (0x02) |
| 1 | Button bitmap (left, right, middle) |
| 2-3 | X delta (i16 LE) |
| 4-5 | Y delta (i16 LE) |
| 6-7 | Reserved |

Mouse events are sent to both the active app and the compositor (compositor always receives mouse for cursor tracking).

---

## 6. Compositor

### Framebuffer protocol

Apps communicate with the compositor via 4 MB shared memory regions:

```
Offset 0: FramebufferHeader (4096 bytes, page-aligned)
Offset 4096: Raw pixel data (BGRA/RGBA, row-major)
```

The header contains display dimensions, pixel format, and an atomic frame counter. The compositor initializes the header after mapping; apps wait for a magic value (0x5A414746) before rendering.

### Compositing

- The compositor draws app framebuffers in least-recently-active order (back to front)
- The active app is drawn last (foreground)
- Mouse cursor is rendered on top of everything
- If an app hasn't updated its framebuffer, the previous content is preserved

### Active app

App_manager tracks which app is currently active. The active app:
- Is rendered on top of all other apps
- Is the only app that receives keyboard events from the USB driver
- Receives mouse events (along with the compositor which always gets mouse)

When a new app is spawned, it becomes the active app. Mouse clicks on a different window can change the active app (compositor reports click location to app_manager).

---

## 7. Test scenario

hello_app demonstrates the full IPC chain:
1. Prints "Hello from desktopOS!" to serial via serial_driver
2. Connects to compositor, renders a test pattern (colored rectangle with title bar)
3. Connects to usb_driver, receives keyboard/mouse HID events
4. Echoes keystrokes to serial (with HID-to-ASCII conversion)

### Expected serial output

```
root: spawned device_manager
root: spawned app_manager
device_manager: spawned serial_driver
device_manager: spawned usb_driver
device_manager: spawned compositor
device_manager: mouse channel created
compositor: display 1280x800 mapped
app_manager: spawned hello_app
usb: xHCI controller initialized
usb: found keyboard (boot protocol)
usb: found mouse (boot protocol)
Hello from desktopOS!
compositor: mouse channel connected
compositor: app framebuffer connected
hello_app: framebuffer 1280x800 connected
hello_app: USB input connected
usb: mouse channel connected
usb: data channel connected
```

---

## 8. Build and run

```bash
cd desktopOS && zig build
cd .. && zig build -Dprofile=desktop
zig build run -Dprofile=desktop
```

The desktop profile automatically uses GTK display, QEMU emulated xHCI controller with USB keyboard and mouse devices, and KVM acceleration with Intel IOMMU.

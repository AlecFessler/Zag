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
│   └── usb_driver
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
| hello_app | Receives USB input events, echoes to serial console | No |

### Restartability

- device_manager and app_manager automatically restart on crash. On restart, they recover existing handles (device regions, SHM, child processes) from their permission view.
- Drivers are restartable by default.
- Apps are NOT restartable by default. The app_manager can grant restart capability to specific apps that have reason to be restartable.

---

## 3. IPC channels

Processes communicate via shared memory channels brokered by parent processes:

- **Command channels**: Each parent creates a 4 KB SHM region for each child, used for connection management (requesting, granting).
- **Data channels**: 16 KB bidirectional ring buffers with CRC32 integrity, created on demand when two processes need to communicate.

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

Currently supported:

| Driver | Device | Status |
|--------|--------|--------|
| serial_driver | UART 16550 | Working |
| usb_driver | xHCI USB host controller (keyboard + mouse HID) | Working |

Root passes all device handles to device_manager. Device_manager decides which drivers to spawn based on device class.

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

---

## 6. Test scenario

hello_app demonstrates the full IPC chain:
1. Prints "Hello from desktopOS!" to serial via serial_driver
2. Connects to usb_driver, receives keyboard/mouse HID events
3. Echoes keystrokes to serial (with HID-to-ASCII conversion)

### Expected serial output

```
root: spawned device_manager
root: spawned app_manager
device_manager: spawned serial_driver
device_manager: spawned usb_driver
app_manager: spawned hello_app
app_manager: connected to device_manager
device_manager: notified app_manager of drivers
usb: xHCI controller initialized
usb: found keyboard (boot protocol)
usb: found mouse (boot protocol)
Hello from desktopOS!
hello_app: USB input connected
[keystrokes echoed here]
```

---

## 7. Build and run

```bash
cd desktopOS && zig build
cd .. && zig build -Dprofile=desktop
zig build run -Dprofile=desktop -Ddisplay none
```

The desktop profile automatically adds QEMU emulated xHCI controller with USB keyboard and mouse devices.

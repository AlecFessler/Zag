# Mouse Protocol

## Overview

The mouse protocol carries relative pointer reports from a USB HID driver (side B) to a consumer (side A) over an SHM channel. It is unidirectional -- the consumer does not send commands back to the driver.

Any device producing relative pointer data (mouse, trackball, touchpad in relative mode) can speak this protocol.

## Identity

- **Protocol ID:** `Protocol.mouse` (value 3)
- **SHM size:** 4096 bytes (1 page)

## Wire Format

All multi-byte fields are little-endian.

### B->A Commands

#### MOUSE_EVENT (0x01)

```
tag:      u8     -- 0x01
buttons:  u16    -- bitfield of pressed buttons
dx:       i16    -- relative X motion
dy:       i16    -- relative Y motion
scroll_v: i8     -- vertical scroll (positive = up)
scroll_h: i8     -- horizontal scroll (positive = right)
```

Wire size: 9 bytes (1 tag + 8 payload).

### A->B Commands

None. The protocol is unidirectional.

## Button Bits

```
bit 0:     left
bit 1:     right
bit 2:     middle
bit 3:     back
bit 4:     forward
bits 5-15: auxiliary (device-specific)
```

Unused bits must be zero. The driver maps the HID report's button bitfield directly into this field regardless of device capability -- a 3-button mouse simply leaves bits 3-15 clear.

## Roles

### Side A -- Client (consumer)

Any process that consumes relative pointer input. Discovers the driver via broadcast table using `Protocol.mouse` and connects with `Channel.connectAsA`.

### Side B -- Server (USB HID driver)

Translates incoming HID reports into MOUSE_EVENT messages. One channel per connected consumer. The driver parses the HID report descriptor to determine the device's button count and scroll capabilities, then extracts the appropriate fields from each interrupt transfer.

## Public API

### `connectToServer(perm_view_addr: u64) ConnectError!Client`

Discovers the mouse server (USB HID driver) via the broadcast table and establishes a channel. Returns a `Client` ready to receive mouse events, or:

- `error.ServerNotFound` -- no mouse server is broadcasting yet.
- `error.ChannelFailed` -- SHM allocation or grant failed.

Callers should retry on `ServerNotFound` if the USB driver has not started yet.

### `Client` (consumer, side A)

- `Client.init(chan: *Channel) Client` -- wraps a connected channel.
- `Client.recv() ?Message` -- reads the next message from the ring buffer. Returns `null` if no message is available or on parse error.

### `Server` (USB HID driver, side B)

- `Server.init(chan: *Channel) Server` -- wraps a connected channel.
- `Server.send(event: MouseEvent) !void` -- serializes and sends a mouse event. Returns `error.ChannelFull` if the ring buffer is full.

### `MouseEvent`

```
buttons:  u16  -- button bitfield
dx:       i16  -- relative X motion
dy:       i16  -- relative Y motion
scroll_v: i8   -- vertical scroll
scroll_h: i8   -- horizontal scroll
```

### Button Constants

```
BTN_LEFT:    u16 = 1 << 0
BTN_RIGHT:   u16 = 1 << 1
BTN_MIDDLE:  u16 = 1 << 2
BTN_BACK:    u16 = 1 << 3
BTN_FORWARD: u16 = 1 << 4
```

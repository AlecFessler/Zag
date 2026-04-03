# Keyboard Protocol

## Overview

The keyboard protocol carries key press/release events from a USB HID driver (side B) to a consumer (side A) over an SHM channel. The consumer can send LED state back to the driver to control physical indicator lights.

Key repeat is a consumer-side policy. The driver reports only physical state transitions.

## Identity

- **Protocol ID:** `Protocol.keyboard` (value 2)
- **SHM size:** 4096 bytes (1 page)

## Wire Format

All multi-byte fields are little-endian.

### B->A Commands (driver -> consumer)

#### KEY_EVENT (0x01)

```
tag:       u8    -- 0x01
keycode:   u16   -- USB HID usage code (little-endian)
state:     u8    -- 0 = released, 1 = pressed
modifiers: u8    -- bitfield of held modifier keys
```

Wire size: 5 bytes (1 tag + 4 payload).

### A->B Commands (consumer -> driver)

#### SET_LEDS (0x10)

```
tag:  u8  -- 0x10
leds: u8  -- bitfield of LED states
```

Wire size: 2 bytes (1 tag + 1 payload).

The driver translates this into a HID output report to update the physical indicators.

## Modifiers

```
bit 0: left ctrl
bit 1: left shift
bit 2: left alt
bit 3: left gui
bit 4: right ctrl
bit 5: right shift
bit 6: right alt
bit 7: right gui
```

Matches the USB HID modifier byte. The driver passes this through directly from the HID report.

## LEDs

```
bit 0: num lock
bit 1: caps lock
bit 2: scroll lock
bits 3-7: reserved (must be zero)
```

Matches USB HID LED usage ordering for bits 0-2. Reserved bits allow future extension without protocol changes.

## Roles

### Side A -- Client (consumer)

Any process that consumes keyboard input. Discovers the driver via broadcast table using `Protocol.keyboard` and connects with `connectToServer`. Responsible for repeat policy and LED toggling logic.

### Side B -- Server (USB HID driver)

Translates incoming HID reports into KEY_EVENT messages and applies SET_LEDS to the hardware. One channel per connected consumer. Broadcasts `Protocol.keyboard` and accepts incoming SHM connections.

## Public API

### `connectToServer(perm_view_addr: u64) ConnectError!Client`

Discovers the keyboard server (USB HID driver) via the broadcast table and establishes a channel. Returns a `Client` ready to receive key events, or:

- `error.ServerNotFound` -- no keyboard server is broadcasting yet.
- `error.ChannelFailed` -- SHM allocation or grant failed.

Callers should retry on `ServerNotFound` if the USB driver has not started yet.

### `Client` (consumer, side A)

- `Client.init(chan: *Channel) Client` -- wraps a connected channel.
- `Client.recv() ?Message` -- reads the next key event from the ring buffer. Returns `null` if no message is available or on parse error.
- `Client.sendLeds(leds: Leds) !void` -- sends LED state to the driver. Returns `error.ChannelFull` if the ring buffer is full.

### `Server` (USB HID driver, side B)

- `Server.init(chan: *Channel) Server` -- wraps a connected channel.
- `Server.send(event: Event) !void` -- serializes and sends a key event. Returns `error.ChannelFull` if the ring buffer is full.
- `Server.recvLeds() ?Leds` -- reads the next LED command from the consumer. Returns `null` if no message is available.

### `Event`

```
keycode:   u16       -- USB HID usage code
state:     State     -- .released or .pressed
modifiers: Modifiers -- bitfield of held modifier keys
```

### `Modifiers`

Packed struct matching the USB HID modifier byte. Named fields: `l_ctrl`, `l_shift`, `l_alt`, `l_gui`, `r_ctrl`, `r_shift`, `r_alt`, `r_gui`.

### `Leds`

Packed struct for physical LED indicators. Named fields: `num_lock`, `caps_lock`, `scroll_lock`.

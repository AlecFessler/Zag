# Display Protocol

## Overview

The display protocol carries render surface allocation from a display server (side B) to an app (side A), and coordinates double-buffered framebuffer submission. The command channel is a small 4K SHM ring buffer. Framebuffers are separate flat SHM regions granted by the client to the server.

All pixel data is BGRA, 32 bits per pixel.

## Identity

- **Protocol ID:** `Protocol.display` (value 1)
- **Command channel SHM size:** 4096 bytes (1 page)
- **Framebuffer protocol ID:** `Protocol.framebuffer` (value 6) — used temporarily in FB SHM metadata

## Wire Format (Command Channel)

All multi-byte fields are little-endian.

### B->A Commands (server -> client)

#### RENDER_TARGET (0x01)

```
tag:    u8   -- 0x01
width:  u32  -- surface width in pixels
height: u32  -- surface height in pixels
stride: u32  -- width in pixels (row stride)
magic:  u32  -- unique identifier for this connection
```

Wire size: 17 bytes (1 tag + 16 payload).

Sent once after the client connects. The client uses the magic to tag its framebuffer SHMs.

#### WINDOW_RESIZED (0x02)

Same payload as RENDER_TARGET. Sent when the app's allocation changes. The client must tear down old framebuffers and set up new ones at the new dimensions.

#### FB_READY (0x03)

```
tag: u8 -- 0x03
```

Wire size: 1 byte. Sent after the server has mapped both framebuffer SHMs. The client may now write pixel data.

### A->B Commands (client -> server)

#### FB_SENT (0x10)

```
tag: u8 -- 0x10
```

Wire size: 1 byte. Sent after the client has created and granted both framebuffer SHMs.

#### FRAME_READY (0x11)

```
tag: u8 -- 0x11
```

Wire size: 1 byte. Signals that the current framebuffer contains a complete frame. Both sides swap to the next buffer.

## Framebuffer Setup Dance

1. Server sends RENDER_TARGET with dimensions and magic
2. Client creates 2 flat SHMs of `stride * height * 4` bytes each
3. Client writes temporary metadata into the first 6 bytes of each SHM:
   - `[0]` protocol_id: `u8` = `@intFromEnum(.framebuffer)`
   - `[1-4]` magic: `u32` LE — matches the server's magic
   - `[5]` buffer_index: `u8` — 0 or 1
4. Client grants both SHMs to the server (via the broadcast handle)
5. Client sends FB_SENT on the command channel
6. Server's SHM poll loop encounters SHMs with framebuffer protocol_id, reads magic and index, maps them, associates with the matching connection
7. Server sends FB_READY once both framebuffers are mapped
8. Client overwrites all bytes with pixel data (metadata is no longer needed)

## Double Buffering

After FB_READY, the client writes into framebuffer 0 and sends FRAME_READY. Both sides swap: the client writes into framebuffer 1 next, the server reads framebuffer 0. This continues alternating.

The convention is implicit — no buffer index is sent with FRAME_READY. Both sides track the current buffer independently.

## Resize

1. Server tears down its framebuffer mappings
2. Server sends WINDOW_RESIZED with new dimensions and a new magic
3. Client tears down its old framebuffers (revoke SHM handles, unmap VM)
4. The framebuffer setup dance repeats from step 2

## Roles

### Side A -- Client (app)

Discovers the display server via broadcast table using `Protocol.display` and connects with `connectToServer`. Receives dimensions, creates framebuffer SHMs, renders frames, and signals completion.

### Side B -- Server (display server)

Allocates render surfaces, sends dimensions with a magic identifier, maps client-granted framebuffers, and composites received frames into the final display output. Maintains per-connection state with command channel and framebuffer references.

## Public API

### `connectToServer(perm_view_addr: u64) ConnectError!Client`

Discovers the display server via the broadcast table and establishes a command channel. Returns a `Client`, or:

- `error.ServerNotFound` -- no display server is broadcasting yet.
- `error.ChannelFailed` -- SHM allocation or grant failed.

### `Client` (app, side A)

- `recv() ?ClientMessage` -- reads the next command from the server.
- `setupFramebuffers(info: RenderTarget) !void` -- creates 2 FB SHMs, writes metadata, grants, sends FB_SENT.
- `teardownFramebuffers() void` -- revokes and unmaps both framebuffer SHMs.
- `sendFrameReady() !void` -- sends FRAME_READY, swaps active buffer.
- `pixels() [*]u8` -- pointer to the current write framebuffer (raw bytes).
- `pixelsAsU32() [*]u32` -- pointer to the current write framebuffer (as u32 pixels).

### `Server` (display server, side B)

- `init(chan: *Channel) Server` -- wraps a connected command channel.
- `sendRenderTarget(info: RenderTarget) !void` -- sends dimensions and magic.
- `sendWindowResized(info: RenderTarget) !void` -- tears down old FBs, sends new dimensions.
- `sendFbReady() !void` -- signals framebuffers are mapped and ready.
- `recv() ?ServerMessage` -- reads FB_SENT or FRAME_READY from the client.
- `mapFramebuffer(shm_handle: u64) bool` -- maps a framebuffer SHM, returns true if magic matches.
- `bothFbsMapped() bool` -- true when both framebuffers are mapped.
- `teardownFramebuffers() void` -- unmaps both framebuffer SHMs.
- `readPixels() [*]const u8` -- pointer to the framebuffer the server should read from.
- `swapBuffer() void` -- advances to the next buffer.

### `RenderTarget`

```
width:  u32 -- surface width in pixels
height: u32 -- surface height in pixels
stride: u32 -- row stride in pixels
magic:  u32 -- connection identifier for framebuffer association
```

# SHM Channel Specification

## Overview

Shared memory (SHM) is the singular IPC primitive provided by the kernel. All inter-process communication beyond process spawning is built on top of it. The kernel's role ends at granting SHM handles -- it plays no part in message framing, routing, or delivery. Every abstraction described in this document is a userspace convention implemented by libz and cooperated in by all processes.

A SHM handle can be granted from a process to one of its direct children, or to a process discovered through the global broadcast table. The kernel enforces both via the `grant` syscall. This document describes how processes use these primitives to establish bidirectional communication channels.

## Kernel Primitives

Relevant syscalls:

- `grant(src_handle, target_handle, granted_rights)` -- grants a SHM handle to a target process. If `target_handle < BROADCAST_OFFSET`, the target is resolved from the caller's perms view and the caller must have `grant_to_child`. If `target_handle >= BROADCAST_OFFSET`, the target is resolved from the global broadcast table and the caller must have `grant_to_broadcast`.
- `broadcast(payload)` -- inserts the calling process into the global broadcast table with the given payload. Requires the `broadcast` process right.
- `shm_create(size, rights)` -- allocates a zeroed SHM region.
- `shm_map(shm_handle, vm_handle, offset)` -- maps an SHM region into a VM reservation.

## Broadcast Table

The global broadcast table is a kernel-managed read-only region mapped into the address space of every process holding `grant_to_broadcast`. It appears in the perms view as entry type 6 (`broadcast_table`) with `field0` containing the virtual address of the mapping. Each entry is 16 bytes:

```
handle:  u64  -- broadcast handle for use with grant
payload: u64  -- userspace-defined, kernel treats as opaque
```

The table has a capacity of 256 slots. When a broadcasting process dies, its slot is filled by copying the last entry in and zeroing the vacated slot. Entries are reused -- userspace must not cache handles across observable table mutations.

### Payload Convention

The kernel does not interpret the payload. By convention, the low byte is the `Protocol` identifier (matching `lib.Protocol`). The remaining 7 bytes are reserved and should be zero. Userspace scans the broadcast table for an entry whose payload low byte matches the desired protocol.

## AB Channel

An AB channel is a bidirectional SHM region between exactly two processes: a requester (side A) and a target (side B). It contains two independent SPSC ring buffers, one per direction.

### Header

The Channel header occupies the beginning of the SHM region. All offsets are byte offsets from the start of the SHM mapping.

```
protocol_id:   u8       -- identifies the protocol spoken over this channel
_reserved:     [7]u8    -- must be zero

// Cache line 1 -- written by A-side producer, read by B-side consumer
A_tx:          u64      -- A-side write index (release store on send)
A_cached_rx:   u64      -- A-side cached copy of B_rx
B_rx:          u64      -- B-side read index (release store on receive)
B_cached_tx:   u64      -- B-side cached copy of A_tx
_pad1:         [64]u8

// Cache line 2 -- written by B-side producer, read by A-side consumer
A_rx:          u64      -- A-side read index
A_cached_tx:   u64      -- A-side cached copy of B_tx
B_tx:          u64      -- B-side write index (release store on send)
B_cached_rx:   u64      -- B-side cached copy of A_rx
_pad2:         [64]u8

// Connection state
A_connected:   u64      -- 1 if A-side is connected, 0 if disconnected
B_connected:   u64      -- 1 if B-side is connected, 0 if disconnected

// Layout
base1:         u64      -- byte offset to the A->B ring buffer
base2:         u64      -- byte offset to the B->A ring buffer
capacity:      u64      -- size in bytes of each ring buffer half
                          = (shm_size - sizeof(Channel)) / 2
```

### SPSC Queue Design

The channel contains two independent SPSC ring buffers. Side A is always the requester; side B is always the target. Each direction has its own producer index (tx) and consumer index (rx).

Producer and consumer indices are on separate cache lines to prevent false sharing. Each side maintains a cached copy of the other side's index, eliminating cross-cache-line reads in the common case.

### SPSC Invariants

- **Writer**: validates `HEADER_SIZE + message_len <= available_space` before writing. Returns `error.ChannelFull` if not. Writes all bytes then advances tx with a release store.
- **Reader**: performs an acquire load on the peer's tx before reading any bytes.

No lock is required -- the release/acquire pair guarantees a reader never observes a partially written message.

### Message Format

```
[ len: u64       ]  -- byte length of the payload
[ payload: bytes ]  -- arbitrary bytes, protocol-defined
```

The 8-byte length prefix is the only framing imposed by the ring buffer layer. Payload structure is entirely defined by `protocol_id`.

### Initialization While Sole Owner

The requester (side A) allocates the SHM region via `shm_create`, maps it locally, and writes the complete header -- `protocol_id`, `base1`, `base2`, `capacity`, and all zeroed indices -- before calling `grant`. `grant` is the publication barrier: all header writes must complete before the handle is granted to side B.

## Connection Establishment

### Service Side (side B)

1. Call `broadcast(protocol_id)` where `protocol_id` is the `Protocol` enum value of the offered service (placed in the low byte of the payload).
2. Poll the perms view for new SHM handles. On receiving one, call `connectAsB(shm_handle, shm_size)` to map it. Read `protocol_id` from the header to dispatch to the correct handler.

### Client Side (side A)

1. Scan the broadcast table for an entry whose payload low byte matches the desired protocol. Read its handle. The helper `findBroadcastHandle(perm_view_addr, protocol)` does this.
2. Call `connectAsA(target_handle, protocol, shm_size)`. This allocates the SHM, initializes the channel header, and grants it to the target. Returns the mapped Channel pointer.
3. Both sides now have the channel mapped and can communicate.

No intermediate routing, no worker threads, no permissions table pressure on any process other than the two endpoints.

## Public API

### `broadcast(protocol_id: u8) !void`

Calls the `broadcast` syscall with `protocol_id` in the low byte of the payload. The process is now visible in the global broadcast table to all processes with `grant_to_broadcast`.

Errors: `error.NoPerm`, `error.TableFull`, `error.DuplicatePayload`.

### `findBroadcastHandle(view_addr: u64, protocol: Protocol) ?u64`

Scans the broadcast table (found via perm view entry type 6) for a provider of the given protocol. Returns the broadcast handle or null.

### `Channel.connectAsA(target_handle: u64, protocol: Protocol, shm_size: u64) ?*Channel`

Allocates and initializes the SHM region, grants it to `target_handle`. The target can be a child process handle or a broadcast table handle -- the caller is responsible for discovery. Returns the mapped Channel pointer or null on failure.

### `Channel.connectAsB(shm_handle: u64, shm_size: u64) ?*Channel`

Maps a granted SHM handle. Does not reinitialize the header -- the requester already wrote it. Returns the Channel pointer or null on failure.

### `Channel.sendMessage(side: Side, msg: []const u8) error{ChannelFull}!void`

Writes a message with an 8-byte length prefix and advances the tx index with a release store. Returns `error.ChannelFull` if insufficient space. Does not check peer connection state -- writing to the ring buffer before the peer connects is valid (the grant is the publication barrier).

### `Channel.receiveMessage(side: Side, out: []u8) error{Disconnected}!?u64`

Acquire-loads the peer's tx, reads the next message into `out`. Returns the number of bytes read, or null if no message is available. If no data is available and the peer's connected flag is cleared, returns `error.Disconnected`. Messages larger than `out.len` are silently skipped to unblock the ring.

### `Channel.disconnect(side: Side, shm_handle: u64, vm_handle: u64) void`

Clears this side's connected flag (release store), then revokes both the SHM handle (unmaps the backing memory) and the VM handle (frees the address range).

## Runtime Integration

Non-root processes enter through `_start`, which sets `perm_view_addr` before calling `app.main`. No mandatory background worker thread is started. Services that accept inbound connections are responsible for polling their own perms view for new SHM handles.

## Summary of Design Principles

- The kernel enforces two grant paths: parent to child (`grant_to_child`) and any process to broadcast target (`grant_to_broadcast`). Everything else is userspace.
- Service discovery is via the global broadcast table. Payload convention puts `protocol_id` in the low byte.
- Connection establishment is two steps: the requester allocates and initializes the SHM, then grants directly to the target handle. No intermediate routing.
- The channel header is initialized by the requester while sole owner, before `grant` is called. `grant` is the publication barrier.
- SPSC ordering with cache-line-separated indices eliminates locks on the hot path.
- No mandatory background worker thread. Services manage their own connection acceptance.

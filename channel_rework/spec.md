# Channel Discovery & Brokering Protocol Specification

## Overview

Processes communicate via shared memory channels. A process advertises itself by making itself discoverable — other processes observe this in their discovery tables and can then request a channel. The channel request is brokered by walking the process tree to the lowest common ancestor, which creates the shared memory and passes the handle down to both sides.

## Core Concepts

### Semantic ID

An 8-byte tree address identifying a process's position in the process tree. Each byte represents one level (root is implicit, so byte 0 = root's children). Child indices are 1-63 (0 = unused/no level). Maximum tree depth: 8.

- `depth(id)` — number of non-zero bytes (0 for root)
- `isAncestor(a, b)` — true if b is in the subtree rooted at a (strict)
- `eql(a, b)` — true if a and b are the same node

### Channel ID

A u64 value analogous to a port number in networking. Protocol definitions declare well-known channel IDs. When a process requests a channel to a target, it specifies the channel ID so both sides can identify the channel's purpose. If a process has multiple unmapped SHM handles pending, the channel ID disambiguates them.

### Command Channel

A bidirectional SPSC ring buffer between every parent-child pair, created at process spawn. Two directions:
- **A-side** (child -> parent): child enqueues, parent dequeues
- **B-side** (parent -> child): parent enqueues, child dequeues

Each direction has 256 command slots with u8 wrapping indices and cache-line-separated cursors.

### Discovery Table

A shared memory region for each process, writable by the parent, read-only by the owning process. Contains up to 256 entries, each a `(SemanticID, ProtocolID)` tuple identifying discoverable processes and their protocols.

### Channel

A bidirectional byte-stream ring buffer over shared memory. The SHM region contains a header (cursors, padding, metadata including `channel_id`) followed by two half-buffers: A's TX (B's RX) and B's TX (A's RX). Messages are framed with a 16-byte header (u64 checksum + u64 length).

## Commands

All commands have a 3-element u64 payload.

| Command | Direction | Payload | Description |
|---|---|---|---|
| `make_discoverable` | UP (child->parent) | `{semantic_id, ttl, protocol_id}` | Register in discovery tables |
| `request_channel` | UP (child->parent) | `{src_semantic_id, target_semantic_id, channel_id}` | Request a channel to a target |
| `new_discovery_entry` | DOWN (parent->child) | `{entry_index, 0, 0}` | Notify child of new discovery table entry |
| `forward_channel_handle` | DOWN (parent->child) | `{channel_id, target_semantic_id, 0}` | Pass SHM handle toward target |
| `evict_discovery_entry` | DOWN (parent->child) | `{semantic_id, 0, 0}` | Remove entries from dead process's subtree |

## Protocol: Make Discoverable

**Purpose**: A process advertises itself so that every process in the subtree rooted N levels above it can observe it in their discovery tables.

**Behavior**:

1. Process sends `make_discoverable(my_id, ttl, protocol)` UP to parent
2. Parent receives the command on the child's A-side. Parent then:
   a. Adds `Entry{id, protocol}` to ALL children's discovery tables
   b. Sends `new_discovery_entry(index)` DOWN to each child on their B-side
   c. Decrements TTL. If TTL > 0 and parent has a parent, forwards `make_discoverable(id, ttl-1, protocol)` UP
   d. If TTL = 0 or at root, the command is dropped
3. When a child's worker thread receives `new_discovery_entry(index)`:
   a. Reads the entry from its own discovery table at that index
   b. Copies it into ALL of its children's discovery tables
   c. Sends `new_discovery_entry(new_index)` DOWN to each child

**Result**: The TTL controls how many hops UP the message travels. At each hop, the entry is written into every discovery table in that process's subtree. So a TTL of N makes the process visible to every process in the subtree rooted N levels above it.

## Protocol: Request Channel

**Purpose**: Establish a bidirectional `Channel` between two processes. One side (the requester / side A) initiates after observing the target in its discovery table.

**Behavior**:

1. Process (side A / requester) sends `request_channel(my_id, target_id, channel_id)` UP to parent
2. Each parent checks: am I the target (`eql`), or am I an ancestor of the target (`isAncestor`)?
   - **NO**: Forward `request_channel` UP to own parent
   - **YES, I am the target** (`eql(my_id, target_id)`): This process IS the target. Create SHM, map it, initialize the Channel header via `Channel.init`, set `Channel.channel_id` to the requested value. Then find which child's subtree contains the source, grant SHM handle to that child, send `forward_channel_handle(channel_id, src_id)` DOWN, then unmap and revoke own access. The target keeps its own handle for `connectAsB`.
   - **YES, I am an ancestor** (`isAncestor(my_id, target_id)`): This process is the LCA. Proceed to brokering.
3. **Brokering** (at LCA, when LCA is not the target):
   a. Create SHM of appropriate size
   b. Map it, initialize the Channel header, set `Channel.channel_id` to the requested value
   c. Find which direct child's subtree contains the source semantic ID
   d. Find which direct child's subtree contains the target semantic ID
   e. Grant the SHM handle to both children's process handles
   f. Send `forward_channel_handle(channel_id, target_id)` DOWN to the child leading toward target
   g. Send `forward_channel_handle(channel_id, src_id)` DOWN to the child leading toward source
   h. Unmap and revoke own SHM access
4. **Forwarding** (at intermediate nodes receiving `forward_channel_handle`):
   a. New SHM handle appears in perm_view (poll until visible)
   b. Map it, verify `Channel.channel_id` matches the command's channel_id
   c. If `target_semantic_id == my_semantic_id`: this is the final destination. Push to pending channel queue for the main thread. Do not auto-map for application use.
   d. Else: find which child's subtree contains the target, grant handle to that child, send `forward_channel_handle` DOWN, revoke own access and unmap

**Result**: Both the source and target processes receive the channel via `awaitChannel(channel_id)` which returns a `*Channel` pointer to the mapped SHM.

## Protocol: Channel Connection

Waiting for a channel uses a futex-based mechanism. `awaitChannel(channel_id, timeout_ns)` blocks until the worker thread delivers a channel with the matching channel_id, or times out. Returns `?*Channel`.

Internally, a 32-entry wait array tracks pending waiters:
- State 0: slot free
- State 1: waiter is waiting (futex_wait on this slot)
- State 2: channel arrived (worker sets this + futex_wake)

The waiter finds the first free slot, writes state=1 and the desired channel_id, then enters a futex_wait loop with periodic timeouts to avoid missed-wake races (check, see not ready, wake happens before wait). When the worker delivers a channel, it scans the array for a matching channel_id with state=1, writes the Channel pointer, sets state=2, and does futex_wake. The waiter clears the slot to 0 when it wakes.

After receiving the channel:

- **Side A (requester)**: The Channel header is already initialized by the broker with the correct `channel_id`. Side A verifies it matches and begins using the channel.
- **Side B (target)**: Reads `Channel.channel_id` to identify the protocol. Does NOT re-initialize the channel. If the SHM was already mapped (LCA-is-target case, where `shm_map` returns an error), this is expected — the channel is already accessible.

Note: `shm_map` returns `E_INVAL` on duplicate mappings (not idempotent). When the LCA is the target, the worker already mapped the SHM to write the channel_id. `connectAsB` must handle this by treating the map error as "already mapped" and proceeding.

## Protocol: Child Death

When a child process dies, its perm_view entry type changes to `ENTRY_TYPE_DEAD_PROCESS`.

**Behavior**:

1. Worker thread detects the dead process entry in perm_view (matching a known child proc handle)
2. Evict all discovery table entries originating from that child's subtree:
   - Remove entries where `isAncestor(dead_child_id, entry.id)` or `eql(dead_child_id, entry.id)` from ALL other children's discovery tables
   - Send `evict_discovery_entry(dead_child_id)` DOWN to all remaining children
3. Clean up resources:
   - Clear command channel, discovery table, and proc handle for that child slot
   - Reset the child index bit in the bitmap so it can be reused
   - Unmap the dead child's SHM regions
4. Revoke any in-flight `forward_channel_handle` SHM handles destined for the dead subtree

When a child's worker thread receives `evict_discovery_entry(semantic_id)`:
1. Remove matching entries from all of its children's discovery tables
2. Forward `evict_discovery_entry` DOWN to all children

---

## Implementation Notes

### Worker Thread

Every process (including root) spawns a worker thread at startup (in `_start`, before `app.main`). The worker runs an infinite loop:

```
loop:
  poll parent command channel B-side
  poll all child command channels A-side
  check perm_view for dead children
  if no work: thread_yield
```

### Cache-Line Separation

CommandChannel cursors for each direction (A and B) must be on separate cache lines to avoid false sharing. The comptime assert verifies this via `@offsetOf`.

### Cross-Process Volatile Access

Discovery table and Channel ring buffer data are in SHM shared between processes mapping different virtual addresses. LLVM may optimize away reads/writes it considers dead within a single compilation unit. All cross-process SHM field accesses must use `volatile` pointers (for data fields) or `@atomicLoad`/`@atomicStore` (for cursor fields). The seqlock's `writeBegin`/`writeEnd` are still called on the writer side to maintain the generation counter, but the reader uses volatile byte access rather than the seqlock's `readBegin`/`readRetry` because the futex-based seqlock reader blocks indefinitely across process boundaries.

### Discovery Table Writes

The parent writes to a child's discovery table using volatile stores for `entries`, `entries_len`, and the seqlock gen counter (via `writeBegin`/`writeEnd`). The `addEntry` and `evictEntry` methods use volatile pointers internally.

### SHM Handle Detection

When `forward_channel_handle` arrives, the worker scans the perm_view for a new `ENTRY_TYPE_SHARED_MEMORY` entry not in its known set, polling with `thread_yield` until it appears.

### Channel Sizing

CommandChannel with two 256-entry buffers fits in ~5 pages. `alignToPages(@sizeOf(CommandChannel))` computes the exact SHM allocation size.

### Root Process

Root has no parent (`parent_command_channel == null`). `make_discoverable` commands with remaining TTL at root are dropped. `request_channel` at root means root is the LCA for all processes.

### Pending Channel Buffer

When `deliverChannel` is called but no `awaitChannel` wait slot matches the channel_id, the channel is buffered in `pending_channels` (up to 32 entries). When `awaitChannel` is later called, it checks the pending buffer first before blocking. This handles the race where a channel handle arrives before the main thread registers its wait slot. Uses atomic load/store on `pending_channel_count` for thread safety between worker and main thread.

### Propagated Entries Buffer

When a discovery entry is added to children's DTs (via `handleMakeDiscoverable` or `handleNewDiscoveryEntry`), it is also appended to a per-process `propagated_entries` buffer. When a new child is spawned (via `spawn_child`), all buffered entries are copied into the new child's discovery table. This prevents the race where `make_discoverable` commands arrive and are processed before all children exist — late-spawned children receive entries from the buffer at creation time.

### Channel Ring Buffer Base Address

The Channel header stores `mid` (half-buffer size) but computes the ring buffer base address relative to `self` at runtime (`@intFromPtr(self) + @sizeOf(Channel)`), NOT as an absolute VA. This is required because sender and receiver map the same SHM at different virtual addresses.

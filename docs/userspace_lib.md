# Zag Userspace Library Reference

The userspace library (`userspace/lib/`) provides the core building blocks for all Zag userspace programs. It is imported as `lib` by applications.

---

## Modules

| Module | Import | Purpose |
|--------|--------|---------|
| `syscall` | `lib.syscall` | Raw syscall wrappers |
| `perms` | `lib.perms` | Capability right types and device enums |
| `perm_view` | `lib.perm_view` | Permissions view entry decoding |
| `sync` | `lib.sync` | Futex-based synchronization primitives |
| `crc32` | `lib.crc32` | CRC32 checksum |
| `channel` | `lib.channel` | SPSC ring buffer data channel |
| `shm_protocol` | `lib.shm_protocol` | SHM brokering protocol (command channels) |
| `testing` | `lib.testing` | Test framework (pass/fail/expect helpers) |

---

## syscall

Raw syscall wrappers. Each function maps 1:1 to a kernel syscall.

### Memory
- `vm_reserve(hint: u64, size: u64, rights: u64) -> SyscallResult2` — reserve VA range. Returns handle + vaddr.
- `vm_perms(handle: u64, offset: u64, size: u64, rights: u64) -> i64` — change sub-range permissions.
- `shm_create(size: u64) -> i64` — create shared memory, returns handle.
- `shm_map(shm_handle: u64, vm_handle: u64, offset: u64) -> i64` — map SHM into reservation.
- `shm_unmap(shm_handle: u64, vm_handle: u64) -> i64` — unmap SHM.
- `mmio_map(device_handle: u64, vm_handle: u64, offset: u64) -> i64` — map MMIO device.
- `mmio_unmap(device_handle: u64, vm_handle: u64) -> i64` — unmap MMIO device.

### Process / Thread
- `proc_create(elf_ptr: u64, elf_len: u64, rights: u64) -> i64` — spawn child process.
- `thread_create(entry: *fn, arg: u64, stack_pages: u64) -> i64` — spawn thread.
- `thread_exit() -> noreturn` — exit current thread.
- `thread_yield() -> void` — yield timeslice.
- `set_affinity(core_mask: u64) -> i64` — set core affinity.

### Capabilities
- `grant_perm(src: u64, target_proc: u64, rights: u64) -> i64` — grant capability to child.
- `revoke_perm(handle: u64) -> i64` — revoke capability.
- `disable_restart() -> i64` — permanently disable restart for self + descendants.

### Synchronization
- `futex_wait(addr: *const u64, expected: u64, timeout_ns: u64) -> i64` — block if `*addr == expected`.
- `futex_wake(addr: *const u64, count: u64) -> i64` — wake up to `count` waiters.

### Device I/O
- `ioport_read(device_handle: u64, offset: u64, width: u64) -> i64` — read from port I/O device.
- `ioport_write(device_handle: u64, offset: u64, width: u64, value: u64) -> i64` — write to port I/O device.

### System
- `write(msg: []const u8) -> void` — debug serial output.
- `clock_gettime() -> i64` — monotonic nanoseconds since boot.
- `shutdown() -> noreturn` — power off machine (requires shutdown permission).

### Constants
- `PAGE4K: u64 = 4096`

### Types
- `SyscallResult2 = struct { val: i64, val2: u64 }` — dual-return for vm_reserve.
- `SyscallNum` — enum of all syscall numbers.

---

## perms

Capability right structures mirroring the kernel's permission model.

### Types

```zig
VmReservationRights: packed struct(u8)
    read, write, execute, shareable, mmio
    fn bits(self) -> u64

ProcessRights: packed struct(u16)
    grant_to, spawn_thread, spawn_process, mem_reserve,
    set_affinity, restart, shm_create, device_own, shutdown
    fn bits(self) -> u64

SharedMemoryRights: packed struct(u8)
    read, write, execute, grant
    fn bits(self) -> u64

DeviceRegionRights: packed struct(u8)
    map, grant
    fn bits(self) -> u64

DeviceType: enum(u8)
    mmio = 0, port_io = 1

DeviceClass: enum(u8)
    network = 0, serial = 1, storage = 2, display = 3,
    timer = 4, usb = 5, unknown = 0xFF
```

---

## perm_view

Decode the user permissions view mapped into every process at launch. The perm view address is passed as the `arg` parameter to the initial thread.

### Constants
- `ENTRY_TYPE_PROCESS = 0`
- `ENTRY_TYPE_VM_RESERVATION = 1`
- `ENTRY_TYPE_SHARED_MEMORY = 2`
- `ENTRY_TYPE_DEVICE_REGION = 3`
- `ENTRY_TYPE_EMPTY = 0xFF`

### UserViewEntry (32 bytes, extern struct)
- `handle: u64` — monotonic handle ID. `U64_MAX` = empty.
- `entry_type: u8` — one of the constants above.
- `rights: u16` — capability rights.
- `field0: u64` — type-specific. For vm_reservation: start addr. For shared_memory: size. For device_region: encoded metadata.
- `field1: u64` — type-specific. For vm_reservation: size. For device_region: PCI info.

### Device Entry Helpers
- `entry.deviceType() -> u8` — 0=mmio, 1=port_io
- `entry.deviceClass() -> u8` — DeviceClass enum value
- `entry.deviceSizeOrPortCount() -> u32`
- `entry.pciVendor() -> u16`
- `entry.pciDevice() -> u16`
- `entry.pciClassCode() -> u8`
- `entry.pciSubclass() -> u8`

---

## sync

Futex-based synchronization primitives. All state fields are `u64 align(8)` for futex compatibility. Safe to embed in SHM for cross-process use.

### Mutex
```zig
var m = sync.Mutex.init();
m.lock();
// critical section
m.unlock();
```
Three-state futex mutex: UNLOCKED(0), LOCKED(1), LOCKED_WAITERS(2). Uses CAS for fast uncontended path, futex_wait for contention.

### Condvar
```zig
var cv = sync.Condvar.init();
// Waiter:
mutex.lock();
while (!condition) cv.wait(&mutex);
mutex.unlock();
// Signaler:
mutex.lock();
condition = true;
cv.signal();  // or cv.broadcast()
mutex.unlock();
```
Sequence-counter based. `wait` atomically releases mutex and blocks. `signal` wakes one, `broadcast` wakes all.

### Semaphore
```zig
var sem = sync.Semaphore.init(1);
sem.wait();   // decrement (blocks if 0)
sem.post();   // increment (wakes one waiter)
```
Counting semaphore using atomic CAS + futex.

---

## crc32

Software CRC32 (polynomial 0xEDB88320, same as zlib/gzip).

```zig
const checksum = crc32.compute("123456789");  // 0xCBF43926
const partial = crc32.update(0xFFFFFFFF, data);
const final = partial ^ 0xFFFFFFFF;
```

- `compute(data: []const u8) -> u32` — full CRC32.
- `update(crc: u32, data: []const u8) -> u32` — incremental update.

---

## channel

Lock-free SPSC (single-producer, single-consumer) ring buffer for IPC data channels. Designed to live in shared memory between two processes. Uses length-prefixed messages and CRC32 checksums.

### Setup

One side initializes, the other opens:

```zig
// Side A (initializer):
var ch_a = channel.Channel.initAsSideA(shm_base, shm_size);

// Side B (opener):
var ch_b = channel.Channel.openAsSideB(shm_base) orelse return error;
```

Side A writes to ring A, reads from ring B. Side B writes to ring B, reads from ring A. Bidirectional.

### Sending and Receiving

```zig
// Send (returns false if ring full)
_ = ch.send("hello");

// Receive (returns message length or null if empty)
var buf: [1024]u8 = undefined;
if (ch.recv(&buf)) |len| {
    const msg = buf[0..len];
}

// Block until data available
ch.waitForMessage();

// Non-blocking check
if (ch.hasMessage()) { ... }
```

### Wire Format

Messages are length-prefixed: `[u32 len][len bytes data]`. The ring wraps circularly. A CRC32 checksum of the ring data region is updated on each write.

### Memory Layout

```
ChannelHeader (32 bytes):
  magic: u64 (0x5A41475F4348414E)
  version: u16, flags: u16
  ring_a_offset, ring_b_offset, ring_size: u32 each

RingHeader (40 bytes):
  head: u64 (consumer), tail: u64 (producer)
  wake_flag: u64 (futex target)
  checksum: u32, data_size: u32
  [ring data follows inline]
```

Total SHM size splits evenly between two rings. With 4K SHM: ~1.9K data per ring direction.

---

## shm_protocol

SHM brokering protocol for the root service to mediate connections between child processes.

### Architecture

The root service creates a **command channel** (small SHM) with each child at spawn. The command channel contains a **connection table** listing which other services this child is allowed to connect to. The root service populates this table at spawn time based on static compile-time policy.

### Service IDs

```zig
shm_protocol.ServiceId.SERIAL  = 1
shm_protocol.ServiceId.NIC     = 2
shm_protocol.ServiceId.ROUTER  = 3
shm_protocol.ServiceId.CONSOLE = 4
```

### CommandChannel (lives in SHM between root and child)

```zig
const cmd = shm_protocol.mapCommandChannel(perm_view_addr);
```

Root-side setup:
```zig
var cmd: *shm_protocol.CommandChannel = @ptrFromInt(shm_base);
cmd.init();
cmd.addAllowedConnection(ServiceId.NIC);    // child can connect to NIC
cmd.addAllowedConnection(ServiceId.SERIAL); // child can connect to serial
```

### Connection Flow

**Child requests connection:**
```zig
const entry = cmd.requestConnection(ServiceId.NIC) orelse return error;
if (cmd.waitForConnection(entry)) {
    // entry.shm_handle is now valid, map it
}
```

**Root brokers the connection:**
```zig
cmd.waitForAnyRequest();
// Find which child requested, find target child's command channel
// Create data SHM, grant to both, update both connection entries
// Set status = connected, notify both
cmd.notifyChild();
```

**On restart:** SHM handles persist. Process checks `entry.status == connected` and remaps existing SHM instead of re-requesting.

### Constants
- `MAX_CONNECTIONS = 8` per child
- `COMMAND_SHM_SIZE = 4096`

---

## testing

Test framework for the kernel test suite.

- `pass(name: []const u8)` — print `[PASS] name`
- `fail(name: []const u8)` — print `[FAIL] name`
- `expectEqual(name, expected: i64, actual: i64)` — pass if equal, fail with values if not
- `expectOk(name, result: i64)` — pass if >= 0
- `failWithVal(name, expected: i64, actual: i64)` — fail with both values
- `section(name: []const u8)` — print section header
- `printHex(val: u64)` — print hex value
- `printDec(val: u64)` — print decimal value
- `printI64(val: i64)` — print signed value
- `waitUntilNonZero(ptr: *volatile u64)` — futex-wait until `*ptr != 0`
- `waitUntilAtLeast(ptr: *volatile u64, min: u64)` — futex-wait until `*ptr >= min`
- `waitForCleanup(handle: u64)` — poll `revoke_perm` until E_BADCAP (process fully cleaned up)

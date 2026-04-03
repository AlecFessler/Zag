# Filesystem Protocol

## Overview

The filesystem protocol provides stateless file and directory operations from an app (side A) to a filesystem server (side B) over an SHM channel. All read and write operations take explicit paths and offsets -- there is no open/close or server-side cursor.

## Identity

- **Protocol ID:** `Protocol.filesystem` (value 5)
- **SHM size:** 65,536 bytes (64 KiB)

## Wire Format

All multi-byte fields are little-endian.

### A->B Commands (client -> server)

#### MKDIR (0x01)

```
tag:  u8    -- 0x01
path: []u8  -- directory path (remainder of payload)
```

Server responds with OK or ERROR.

#### RMDIR (0x02)

```
tag:  u8    -- 0x02
path: []u8  -- directory path (remainder of payload)
```

Server responds with OK or ERROR.

#### MKFILE (0x03)

```
tag:  u8    -- 0x03
path: []u8  -- file path (remainder of payload)
```

Server responds with OK or ERROR.

#### RMFILE (0x04)

```
tag:  u8    -- 0x04
path: []u8  -- file path (remainder of payload)
```

Server responds with OK or ERROR.

#### READ (0x05)

```
tag:    u8   -- 0x05
offset: u64  -- byte offset into file (little-endian)
size:   u64  -- bytes to read (little-endian)
path:   []u8 -- file path (remainder of payload)
```

Wire size: 1 + 16 + path length. Server responds with DATA or ERROR.

#### WRITE (0x06)

```
tag:      u8   -- 0x06
offset:   u64  -- byte offset into file (little-endian)
path_len: u16  -- length of path in bytes (little-endian)
path:     []u8 -- file path
data:     []u8 -- bytes to write (remainder of payload)
```

Wire size: 1 + 10 + path length + data length. Server responds with OK or ERROR.

#### LS (0x07)

```
tag:  u8    -- 0x07
path: []u8  -- directory path (remainder of payload)
```

Server responds with DATA (newline-separated entry names) or ERROR.

#### STAT (0x08)

```
tag:  u8    -- 0x08
path: []u8  -- file or directory path (remainder of payload)
```

Server responds with STAT or ERROR.

#### RENAME (0x09)

```
tag:       u8   -- 0x09
path1_len: u16  -- length of source path (little-endian)
path1:     []u8 -- source path
path2:     []u8 -- destination path (remainder of payload)
```

Wire size: 1 + 2 + path1 length + path2 length. Server responds with OK or ERROR.

#### TRUNCATE (0x0A)

```
tag:  u8   -- 0x0A
size: u64  -- new file size in bytes (little-endian)
path: []u8 -- file path (remainder of payload)
```

Wire size: 1 + 8 + path length. Server responds with OK or ERROR.

### B->A Responses (server -> client)

#### OK (0x80)

```
tag: u8  -- 0x80
```

Wire size: 1 byte. Operation succeeded.

#### DATA (0x81)

```
tag:  u8    -- 0x81
data: []u8  -- returned data (variable length)
```

#### STAT (0x82)

```
tag:      u8   -- 0x82
size:     u64  -- file size in bytes (little-endian)
type:     u8   -- 0 = file, 1 = directory
created:  u64  -- creation time, nanoseconds since epoch (little-endian)
modified: u64  -- modification time, nanoseconds since epoch (little-endian)
accessed: u64  -- access time, nanoseconds since epoch (little-endian)
```

Wire size: 34 bytes (1 tag + 33 payload).

#### ERROR (0xFF)

```
tag:     u8    -- 0xFF
message: []u8  -- error description (variable length)
```

## Roles

### Side A -- Client (consumer)

Any process that needs file access. Discovers the filesystem server via broadcast table using `Protocol.filesystem` and connects. Responsible for constructing absolute paths and managing offsets.

### Side B -- Server (filesystem driver)

Filesystem server. Manages storage and responds to operations. Sits on top of the NVMe block device driver. Broadcasts `Protocol.filesystem` and accepts incoming SHM connections.

## Public API

### `connectToServer(perm_view_addr: u64) ConnectError!Client`

Discovers the filesystem server via the broadcast table and establishes a channel. Returns a `Client` ready to send commands, or:

- `error.ServerNotFound` -- no filesystem server is broadcasting yet.
- `error.ChannelFailed` -- SHM allocation or grant failed.

Callers should retry on `ServerNotFound` if the NVMe driver has not started yet.

### `Client` (consumer, side A)

- `Client.init(chan: *Channel) Client` -- wraps a connected channel.
- `Client.mkdir(path, resp_buf) ?Response` -- create a directory.
- `Client.rmdir(path, resp_buf) ?Response` -- remove a directory.
- `Client.mkfile(path, resp_buf) ?Response` -- create a file.
- `Client.rmfile(path, resp_buf) ?Response` -- remove a file.
- `Client.read(path, offset, size, resp_buf) ?Response` -- read bytes at offset.
- `Client.write(path, offset, data, resp_buf) ?Response` -- write bytes at offset.
- `Client.ls(path, resp_buf) ?Response` -- list directory contents.
- `Client.stat(path, resp_buf) ?Response` -- get file/directory metadata.
- `Client.rename(src, dst, resp_buf) ?Response` -- rename or move.
- `Client.truncate(path, size, resp_buf) ?Response` -- set file size.

All methods return `null` on timeout (500k yield retries).

### `Server` (filesystem driver, side B)

- `Server.init(chan: *Channel) Server` -- wraps a connected channel.
- `Server.recv(buf) ?Request` -- reads the next request. Returns `null` if no message available.
- `Server.sendOk()` -- sends OK response.
- `Server.sendData(data)` -- sends DATA response.
- `Server.sendStat(info: StatInfo)` -- sends STAT response.
- `Server.sendError(msg)` -- sends ERROR response.

### `Response`

```
union(enum) {
    ok:   void,
    data: []const u8,
    stat: StatInfo,
    err:  []const u8,
}
```

### `StatInfo`

```
size:      u64      -- file size in bytes
file_type: FileType -- .file or .directory
created:   u64      -- nanoseconds since epoch
modified:  u64      -- nanoseconds since epoch
accessed:  u64      -- nanoseconds since epoch
```

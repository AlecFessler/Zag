/// NFSv3 protocol procedures (RFC 1813) and MOUNT protocol.
const lib = @import("lib");

const rpc = @import("rpc.zig");
const xdr = @import("xdr.zig");

const syscall = lib.syscall;

// Ports (skip portmapper, use fixed ports)
pub const NFS_PORT: u16 = 2049;
pub const MOUNT_PORT: u16 = 20048;
pub const LOCAL_PORT: u16 = 799;

// MOUNT procedures
pub const MOUNTPROC_MNT: u32 = 1;

// NFS3 procedures
pub const NFSPROC3_GETATTR: u32 = 1;
pub const NFSPROC3_LOOKUP: u32 = 3;
pub const NFSPROC3_READ: u32 = 6;
pub const NFSPROC3_WRITE: u32 = 7;
pub const NFSPROC3_CREATE: u32 = 8;
pub const NFSPROC3_MKDIR: u32 = 9;
pub const NFSPROC3_REMOVE: u32 = 12;
pub const NFSPROC3_RMDIR: u32 = 13;
pub const NFSPROC3_RENAME: u32 = 14;
pub const NFSPROC3_READDIR: u32 = 16;
pub const NFSPROC3_COMMIT: u32 = 21;

// NFS3 status codes
pub const NFS3_OK: u32 = 0;

// NFS3 file types
pub const NF3REG: u32 = 1;
pub const NF3DIR: u32 = 2;

// NFS3 write stability
pub const UNSTABLE: u32 = 0;

pub const READ_SIZE: u32 = 1024;

pub const FileHandle = struct {
    data: [64]u8 = [_]u8{0} ** 64,
    len: u32 = 0,

    pub fn fromSlice(src: []const u8) FileHandle {
        var fh = FileHandle{};
        const copy_len = @min(src.len, 64);
        @memcpy(fh.data[0..copy_len], src[0..copy_len]);
        fh.len = @intCast(copy_len);
        return fh;
    }

    pub fn slice(self: *const FileHandle) []const u8 {
        return self.data[0..self.len];
    }
};

// ── MOUNT ──────────────────────────────────────────────────────────────

/// Build a MOUNT MNT request. Returns the message length.
pub fn buildMountRequest(buf: []u8, xid_val: u32, export_path: []const u8) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.MOUNT_PROGRAM, rpc.MOUNT_VERSION, MOUNTPROC_MNT);
    p = xdr.writeString(buf, p, export_path);
    return p;
}

/// Parse a MOUNT MNT reply. Returns the root file handle on success.
pub fn parseMountReply(buf: []const u8, xid_val: u32) ?FileHandle {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return null;
    // Mount status
    const status = xdr.readU32(buf, body) orelse return null;
    if (status.val != 0) {
        reportNfsError("MOUNT", status.val);
        return null;
    }
    // File handle (opaque)
    const fh = xdr.readOpaque(buf, status.pos) orelse return null;
    return FileHandle.fromSlice(fh.data);
}

// ── GETATTR ────────────────────────────────────────────────────────────

pub fn buildGetAttrRequest(buf: []u8, xid_val: u32, fh: *const FileHandle) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_GETATTR);
    p = xdr.writeOpaque(buf, p, fh.slice());
    return p;
}

pub const FileAttr = struct {
    ftype: u32 = 0,
    size: u64 = 0,
};

pub fn parseGetAttrReply(buf: []const u8, xid_val: u32) ?FileAttr {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return null;
    const status = xdr.readU32(buf, body) orelse return null;
    if (status.val != NFS3_OK) return null;
    // fattr3: type(4) mode(4) nlink(4) uid(4) gid(4) size(8) ...
    const ftype = xdr.readU32(buf, status.pos) orelse return null;
    // Skip mode, nlink, uid, gid (4*4 = 16 bytes)
    const size = xdr.readU64(buf, ftype.pos + 16) orelse return null;
    return .{ .ftype = ftype.val, .size = size.val };
}

// ── LOOKUP ─────────────────────────────────────────────────────────────

pub fn buildLookupRequest(buf: []u8, xid_val: u32, dir_fh: *const FileHandle, name: []const u8) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_LOOKUP);
    p = xdr.writeOpaque(buf, p, dir_fh.slice());
    p = xdr.writeString(buf, p, name);
    return p;
}

pub fn parseLookupReply(buf: []const u8, xid_val: u32) ?FileHandle {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return null;
    const status = xdr.readU32(buf, body) orelse return null;
    if (status.val != NFS3_OK) {
        reportNfsError("LOOKUP", status.val);
        return null;
    }
    const fh = xdr.readOpaque(buf, status.pos) orelse return null;
    return FileHandle.fromSlice(fh.data);
}

// ── READ ───────────────────────────────────────────────────────────────

pub fn buildReadRequest(buf: []u8, xid_val: u32, fh: *const FileHandle, offset: u64, count: u32) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_READ);
    p = xdr.writeOpaque(buf, p, fh.slice());
    p = xdr.writeU64(buf, p, offset);
    p = xdr.writeU32(buf, p, count);
    return p;
}

pub const ReadResult = struct {
    data: []const u8,
    eof: bool,
};

pub fn parseReadReply(buf: []const u8, xid_val: u32) ?ReadResult {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return null;
    const status = xdr.readU32(buf, body) orelse return null;
    if (status.val != NFS3_OK) {
        reportNfsError("READ", status.val);
        return null;
    }
    // post_op_attr: bool(4) + if true, fattr3 (84 bytes)
    const has_attr = xdr.readU32(buf, status.pos) orelse return null;
    var p = has_attr.pos;
    if (has_attr.val != 0) p += 84; // skip fattr3
    // count(4), eof(4), data(opaque)
    const count_r = xdr.readU32(buf, p) orelse return null;
    const eof = xdr.readU32(buf, count_r.pos) orelse return null;
    const data = xdr.readOpaque(buf, eof.pos) orelse return null;
    return .{ .data = data.data, .eof = eof.val != 0 };
}

// ── READDIR ────────────────────────────────────────────────────────────

pub fn buildReadDirRequest(buf: []u8, xid_val: u32, dir_fh: *const FileHandle, cookie: u64, cookieverf: [8]u8, max_count: u32) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_READDIR);
    p = xdr.writeOpaque(buf, p, dir_fh.slice());
    p = xdr.writeU64(buf, p, cookie);
    // cookieverf (8 bytes, not XDR-encoded, raw)
    if (p + 8 <= buf.len) {
        @memcpy(buf[p..][0..8], &cookieverf);
        p += 8;
    }
    p = xdr.writeU32(buf, p, max_count);
    return p;
}

pub const DirEntry = struct {
    name: []const u8,
    cookie: u64,
};

pub const ReadDirResult = struct {
    entries: [32]DirEntry,
    count: u32,
    eof: bool,
    cookieverf: [8]u8,
};

pub fn parseReadDirReply(buf: []const u8, xid_val: u32) ?ReadDirResult {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return null;
    const status = xdr.readU32(buf, body) orelse return null;
    if (status.val != NFS3_OK) {
        reportNfsError("READDIR", status.val);
        return null;
    }
    // post_op_attr
    const has_attr = xdr.readU32(buf, status.pos) orelse return null;
    var p = has_attr.pos;
    if (has_attr.val != 0) p += 84;
    // cookieverf (8 raw bytes)
    if (p + 8 > buf.len) return null;
    var result = ReadDirResult{
        .entries = undefined,
        .count = 0,
        .eof = false,
        .cookieverf = undefined,
    };
    @memcpy(&result.cookieverf, buf[p..][0..8]);
    p += 8;
    // Entries: each is [bool follows][u64 fileid][string name][u64 cookie]
    while (result.count < 32) {
        const follows = xdr.readU32(buf, p) orelse return null;
        p = follows.pos;
        if (follows.val == 0) break;
        // fileid
        const fileid = xdr.readU64(buf, p) orelse return null;
        // name
        const name = xdr.readOpaque(buf, fileid.pos) orelse return null;
        // cookie
        const cookie = xdr.readU64(buf, name.pos) orelse return null;
        result.entries[result.count] = .{ .name = name.data, .cookie = cookie.val };
        result.count += 1;
        p = cookie.pos;
    }
    // eof
    const eof = xdr.readU32(buf, p) orelse return null;
    result.eof = eof.val != 0;
    return result;
}

// ── WRITE ──────────────────────────────────────────────────────────────

pub fn buildWriteRequest(buf: []u8, xid_val: u32, fh: *const FileHandle, offset: u64, data: []const u8) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_WRITE);
    p = xdr.writeOpaque(buf, p, fh.slice());
    p = xdr.writeU64(buf, p, offset);
    p = xdr.writeU32(buf, p, @intCast(data.len));
    p = xdr.writeU32(buf, p, UNSTABLE); // stability
    p = xdr.writeOpaque(buf, p, data);
    return p;
}

pub fn parseWriteReply(buf: []const u8, xid_val: u32) ?u32 {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return null;
    const status = xdr.readU32(buf, body) orelse return null;
    if (status.val != NFS3_OK) {
        reportNfsError("WRITE", status.val);
        return null;
    }
    // wcc_data: pre_op(bool+opt), post_op(bool+opt)
    const pre = xdr.readU32(buf, status.pos) orelse return null;
    var p = pre.pos;
    if (pre.val != 0) p += 24; // pre_op_attr: size(8) mtime(8) ctime(8)
    const post = xdr.readU32(buf, p) orelse return null;
    p = post.pos;
    if (post.val != 0) p += 84;
    // count(4)
    const count = xdr.readU32(buf, p) orelse return null;
    return count.val;
}

// ── CREATE ─────────────────────────────────────────────────────────────

pub fn buildCreateRequest(buf: []u8, xid_val: u32, dir_fh: *const FileHandle, name: []const u8) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_CREATE);
    p = xdr.writeOpaque(buf, p, dir_fh.slice());
    p = xdr.writeString(buf, p, name);
    // createmode: UNCHECKED (0)
    p = xdr.writeU32(buf, p, 0);
    // sattr3: mode=0644
    p = xdr.writeU32(buf, p, 1); // set_mode = true
    p = xdr.writeU32(buf, p, 0o644);
    p = xdr.writeU32(buf, p, 0); // set_uid = false
    p = xdr.writeU32(buf, p, 0); // set_gid = false
    p = xdr.writeU32(buf, p, 0); // set_size = false
    p = xdr.writeU32(buf, p, 0); // set_atime = DONT_CHANGE
    p = xdr.writeU32(buf, p, 0); // set_mtime = DONT_CHANGE
    return p;
}

pub fn parseCreateReply(buf: []const u8, xid_val: u32) ?FileHandle {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return null;
    const status = xdr.readU32(buf, body) orelse return null;
    if (status.val != NFS3_OK) {
        reportNfsError("CREATE", status.val);
        return null;
    }
    // post_op_fh3: bool(4) + optional fh(opaque)
    const has_fh = xdr.readU32(buf, status.pos) orelse return null;
    if (has_fh.val == 0) return null;
    const fh = xdr.readOpaque(buf, has_fh.pos) orelse return null;
    return FileHandle.fromSlice(fh.data);
}

// ── MKDIR ──────────────────────────────────────────────────────────────

pub fn buildMkdirRequest(buf: []u8, xid_val: u32, dir_fh: *const FileHandle, name: []const u8) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_MKDIR);
    p = xdr.writeOpaque(buf, p, dir_fh.slice());
    p = xdr.writeString(buf, p, name);
    // sattr3: mode=0755
    p = xdr.writeU32(buf, p, 1); // set_mode = true
    p = xdr.writeU32(buf, p, 0o755);
    p = xdr.writeU32(buf, p, 0); // set_uid
    p = xdr.writeU32(buf, p, 0); // set_gid
    p = xdr.writeU32(buf, p, 0); // set_size
    p = xdr.writeU32(buf, p, 0); // set_atime
    p = xdr.writeU32(buf, p, 0); // set_mtime
    return p;
}

pub fn parseMkdirReply(buf: []const u8, xid_val: u32) ?FileHandle {
    return parseCreateReply(buf, xid_val); // same format
}

// ── REMOVE ─────────────────────────────────────────────────────────────

pub fn buildRemoveRequest(buf: []u8, xid_val: u32, dir_fh: *const FileHandle, name: []const u8) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_REMOVE);
    p = xdr.writeOpaque(buf, p, dir_fh.slice());
    p = xdr.writeString(buf, p, name);
    return p;
}

pub fn parseRemoveReply(buf: []const u8, xid_val: u32) bool {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return false;
    const status = xdr.readU32(buf, body) orelse return false;
    return status.val == NFS3_OK;
}

// ── RMDIR ──────────────────────────────────────────────────────────────

pub fn buildRmdirRequest(buf: []u8, xid_val: u32, dir_fh: *const FileHandle, name: []const u8) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_RMDIR);
    p = xdr.writeOpaque(buf, p, dir_fh.slice());
    p = xdr.writeString(buf, p, name);
    return p;
}

pub fn parseRmdirReply(buf: []const u8, xid_val: u32) bool {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return false;
    const status = xdr.readU32(buf, body) orelse return false;
    if (status.val != NFS3_OK) {
        reportNfsError("RMDIR", status.val);
    }
    return status.val == NFS3_OK;
}

// ── RENAME ─────────────────────────────────────────────────────────────

pub fn buildRenameRequest(buf: []u8, xid_val: u32, from_dir_fh: *const FileHandle, from_name: []const u8, to_dir_fh: *const FileHandle, to_name: []const u8) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_RENAME);
    p = xdr.writeOpaque(buf, p, from_dir_fh.slice());
    p = xdr.writeString(buf, p, from_name);
    p = xdr.writeOpaque(buf, p, to_dir_fh.slice());
    p = xdr.writeString(buf, p, to_name);
    return p;
}

pub fn parseRenameReply(buf: []const u8, xid_val: u32) bool {
    const body = rpc.parseReplyHeader(buf, xid_val) orelse return false;
    const status = xdr.readU32(buf, body) orelse return false;
    if (status.val != NFS3_OK) {
        reportNfsError("RENAME", status.val);
    }
    return status.val == NFS3_OK;
}

// ── COMMIT ─────────────────────────────────────────────────────────────

pub fn buildCommitRequest(buf: []u8, xid_val: u32, fh: *const FileHandle) usize {
    var p = rpc.buildCallHeader(buf, xid_val, rpc.NFS_PROGRAM, rpc.NFS_VERSION, NFSPROC3_COMMIT);
    p = xdr.writeOpaque(buf, p, fh.slice());
    p = xdr.writeU64(buf, p, 0); // offset
    p = xdr.writeU32(buf, p, 0); // count (0 = entire file)
    return p;
}

// ── Diagnostics ────────────────────────────────────────────────────────

fn reportNfsError(op: []const u8, status_code: u32) void {
    syscall.write("nfs3: ");
    syscall.write(op);
    syscall.write(" error status=");
    var buf: [10]u8 = undefined;
    var v = status_code;
    var i: usize = 10;
    if (v == 0) {
        i -= 1;
        buf[i] = '0';
    } else {
        while (v > 0) {
            i -= 1;
            buf[i] = '0' + @as(u8, @truncate(v % 10));
            v /= 10;
        }
    }
    syscall.write(buf[i..10]);
    syscall.write("\n");
}

/// Sun RPC (ONC RPC) message framing for NFS over UDP.
/// RFC 5531 — uses AUTH_NONE for simplicity.
const xdr = @import("xdr.zig");

pub const RPC_VERSION: u32 = 2;
pub const MSG_CALL: u32 = 0;
pub const MSG_REPLY: u32 = 1;
pub const AUTH_NONE: u32 = 0;
pub const AUTH_UNIX: u32 = 1;
pub const REPLY_ACCEPTED: u32 = 0;
pub const ACCEPT_SUCCESS: u32 = 0;

pub const MOUNT_PROGRAM: u32 = 100005;
pub const MOUNT_VERSION: u32 = 3;
pub const NFS_PROGRAM: u32 = 100003;
pub const NFS_VERSION: u32 = 3;

/// Build an RPC CALL header (40 bytes).
/// Returns position after the header where procedure args should be written.
pub fn buildCallHeader(buf: []u8, xid: u32, program: u32, version: u32, procedure: u32) usize {
    var p: usize = 0;
    p = xdr.writeU32(buf, p, xid);
    p = xdr.writeU32(buf, p, MSG_CALL);
    p = xdr.writeU32(buf, p, RPC_VERSION);
    p = xdr.writeU32(buf, p, program);
    p = xdr.writeU32(buf, p, version);
    p = xdr.writeU32(buf, p, procedure);
    // Auth credentials: AUTH_UNIX (uid=0, gid=0)
    p = xdr.writeU32(buf, p, AUTH_UNIX);
    p = xdr.writeU32(buf, p, 20); // cred body length: stamp(4) + machine_name(4+0) + uid(4) + gid(4) + gids_count(4)
    p = xdr.writeU32(buf, p, 0); // stamp
    p = xdr.writeU32(buf, p, 0); // machine name length (empty)
    p = xdr.writeU32(buf, p, 0); // uid = root
    p = xdr.writeU32(buf, p, 0); // gid = root
    p = xdr.writeU32(buf, p, 0); // auxiliary gids count
    // Auth verifier: AUTH_NONE
    p = xdr.writeU32(buf, p, AUTH_NONE);
    p = xdr.writeU32(buf, p, 0); // verifier body length
    return p;
}

/// Quick check: does the packet's XID match the expected one?
pub fn xidMatches(buf: []const u8, expected_xid: u32) bool {
    const xid_r = xdr.readU32(buf, 0) orelse return false;
    return xid_r.val == expected_xid;
}

/// Parse an RPC REPLY header. Returns the offset to procedure-specific data,
/// or null if the reply is invalid/rejected.
pub fn parseReplyHeader(buf: []const u8, expected_xid: u32) ?usize {
    // XID
    const xid_r = xdr.readU32(buf, 0) orelse return null;
    if (xid_r.val != expected_xid) return null;
    // Message type
    const type_r = xdr.readU32(buf, xid_r.pos) orelse return null;
    if (type_r.val != MSG_REPLY) return null;
    // Reply status (0 = accepted)
    const status_r = xdr.readU32(buf, type_r.pos) orelse return null;
    if (status_r.val != REPLY_ACCEPTED) return null;
    // Verifier (skip: flavor + body)
    const vflavor_r = xdr.readU32(buf, status_r.pos) orelse return null;
    const vlen_r = xdr.readU32(buf, vflavor_r.pos) orelse return null;
    const after_verifier = vlen_r.pos + vlen_r.val;
    if (after_verifier > buf.len) return null;
    // Accept status (0 = success)
    const accept_r = xdr.readU32(buf, after_verifier) orelse return null;
    if (accept_r.val != ACCEPT_SUCCESS) return null;
    return accept_r.pos;
}

const lib = @import("lib");
const nvme = @import("nvme.zig");

const syscall = lib.syscall;

// ── On-disk layout ──────────────────────────────────────────────────
//
// LBA 0:     Superblock
// LBA 1-8:   Free block bitmap (8 LBAs = 4096 bytes = 32768 bits)
// LBA 9:     Root directory inode
// LBA 10+:   Inodes and data blocks
//
const SUPERBLOCK_MAGIC: u32 = 0x5A414746; // "ZAGF"
const SUPERBLOCK_LBA: u32 = 0;
const BITMAP_START: u32 = 1;
const BITMAP_LBAS: u32 = 8;
const ROOT_INODE_LBA: u32 = 9;
const FIRST_FREE_LBA: u32 = 10;
const LBA_SIZE: u32 = 512;

// Inode types
const INODE_FREE: u8 = 0;
const INODE_FILE: u8 = 1;
const INODE_DIR: u8 = 2;

// Inode layout within an LBA (512 bytes)
const INODE_NAME_MAX: usize = 64;
const INODE_DIRECT_MAX: usize = 64;

// ── Superblock layout (within LBA 0) ────────────────────────────────
//
// bytes 0-3:   magic (SUPERBLOCK_MAGIC)
// bytes 4-7:   root_inode_lba
// bytes 8-11:  next_free_lba (hint for allocation)
//
const SB_OFF_MAGIC: usize = 0;
const SB_OFF_ROOT: usize = 4;
const SB_OFF_NEXT_FREE: usize = 8;

// ── Module state ────────────────────────────────────────────────────
var ctrl: *nvme.Controller = undefined;
var open_inode_lba: u32 = 0; // currently open file (0 = none)

pub fn init(controller: *nvme.Controller) bool {
    ctrl = controller;

    // Read superblock
    if (!ctrl.readSectors(1, SUPERBLOCK_LBA, 1)) {
        syscall.write("fs: failed to read superblock\n");
        return false;
    }

    const buf = ctrl.getReadBuf();
    const magic = readU32(buf, SB_OFF_MAGIC);

    if (magic == SUPERBLOCK_MAGIC) {
        syscall.write("fs: mounted existing filesystem\n");
        return true;
    }

    // Format disk
    syscall.write("fs: formatting disk\n");
    return format();
}

fn format() bool {
    const wbuf = ctrl.getWriteBuf();

    // Write superblock
    @memset(wbuf[0..LBA_SIZE], 0);
    writeU32(wbuf, SB_OFF_MAGIC, SUPERBLOCK_MAGIC);
    writeU32(wbuf, SB_OFF_ROOT, ROOT_INODE_LBA);
    writeU32(wbuf, SB_OFF_NEXT_FREE, FIRST_FREE_LBA);
    if (!ctrl.writeSectors(1, SUPERBLOCK_LBA, 1)) return false;

    // Clear bitmap (all free)
    @memset(wbuf[0..LBA_SIZE], 0);
    var i: u32 = 0;
    while (i < BITMAP_LBAS) : (i += 1) {
        if (!ctrl.writeSectors(1, BITMAP_START + i, 1)) return false;
    }

    // Mark LBAs 0 through ROOT_INODE_LBA as used in bitmap
    if (!ctrl.readSectors(1, BITMAP_START, 1)) return false;
    const rbuf = ctrl.getReadBuf();
    @memcpy(wbuf[0..LBA_SIZE], rbuf[0..LBA_SIZE]);
    var lba: u32 = 0;
    while (lba <= ROOT_INODE_LBA) : (lba += 1) {
        setBitmapBit(wbuf, lba);
    }
    if (!ctrl.writeSectors(1, BITMAP_START, 1)) return false;

    // Write root inode
    @memset(wbuf[0..LBA_SIZE], 0);
    wbuf[0] = INODE_DIR; // type
    const root_name = "/";
    wbuf[2] = @truncate(root_name.len);
    wbuf[3] = 0;
    @memcpy(wbuf[4..][0..root_name.len], root_name);
    // parent = 0 (root is its own parent)
    writeU32(wbuf, 76, ROOT_INODE_LBA);
    if (!ctrl.writeSectors(1, ROOT_INODE_LBA, 1)) return false;

    syscall.write("fs: format complete\n");
    return true;
}

// ── Public filesystem operations ────────────────────────────────────

pub fn mkdir(path: []const u8) bool {
    return createEntry(path, INODE_DIR);
}

pub fn mkfile(path: []const u8) bool {
    return createEntry(path, INODE_FILE);
}

pub fn rmdir(path: []const u8) bool {
    const inode_lba = resolvePath(path) orelse return false;
    if (inode_lba == ROOT_INODE_LBA) return false; // can't remove root

    // Read inode to check type and emptiness
    if (!ctrl.readSectors(1, inode_lba, 1)) return false;
    const buf = ctrl.getReadBuf();
    if (buf[0] != INODE_DIR) return false;
    const block_count = readU32(buf, 80);
    if (block_count != 0) return false; // not empty

    return removeEntry(path, inode_lba);
}

pub fn rmfile(path: []const u8) bool {
    const inode_lba = resolvePath(path) orelse return false;
    if (inode_lba == ROOT_INODE_LBA) return false;

    if (!ctrl.readSectors(1, inode_lba, 1)) return false;
    const buf = ctrl.getReadBuf();
    if (buf[0] != INODE_FILE) return false;

    // Free data blocks
    const block_count = readU32(buf, 80);
    var i: u32 = 0;
    while (i < block_count) : (i += 1) {
        const data_lba = readU32(buf, 84 + i * 4);
        freeBlock(data_lba);
    }

    return removeEntry(path, inode_lba);
}

pub fn openFile(path: []const u8) bool {
    if (open_inode_lba != 0) return false; // already open
    const inode_lba = resolvePath(path) orelse return false;

    if (!ctrl.readSectors(1, inode_lba, 1)) return false;
    const buf = ctrl.getReadBuf();
    if (buf[0] != INODE_FILE) return false;

    open_inode_lba = inode_lba;
    return true;
}

pub fn writeFile(data: []const u8) bool {
    if (open_inode_lba == 0) return false;

    // Read current inode
    if (!ctrl.readSectors(1, open_inode_lba, 1)) return false;
    const rbuf = ctrl.getReadBuf();
    const wbuf = ctrl.getWriteBuf();

    // Copy inode to write buffer for modification
    @memcpy(wbuf[0..LBA_SIZE], rbuf[0..LBA_SIZE]);

    var current_size = readU64(wbuf, 68);
    var block_count = readU32(wbuf, 80);

    // Write data in LBA-sized chunks
    var written: usize = 0;
    while (written < data.len) {
        if (block_count >= INODE_DIRECT_MAX) return false; // out of direct blocks

        const new_lba = allocBlock() orelse return false;
        const chunk_len = @min(data.len - written, LBA_SIZE);

        // Prepare data block in a temporary area
        const data_buf = ctrl.getWriteBuf();
        @memset(data_buf[0..LBA_SIZE], 0);
        @memcpy(data_buf[0..chunk_len], data[written..][0..chunk_len]);
        if (!ctrl.writeSectors(1, new_lba, 1)) return false;

        // Re-read inode since writeSectors used write buffer
        if (!ctrl.readSectors(1, open_inode_lba, 1)) return false;
        @memcpy(ctrl.getWriteBuf()[0..LBA_SIZE], ctrl.getReadBuf()[0..LBA_SIZE]);

        // Update inode with new block
        const wb = ctrl.getWriteBuf();
        writeU32(wb, 84 + block_count * 4, new_lba);
        block_count += 1;
        current_size += chunk_len;
        writeU32(wb, 80, block_count);
        writeU64(wb, 68, current_size);
        if (!ctrl.writeSectors(1, open_inode_lba, 1)) return false;

        written += chunk_len;
    }

    return true;
}

pub fn closeFile() void {
    open_inode_lba = 0;
}

pub fn ls(path: []const u8, out_buf: []u8) usize {
    const dir_lba = resolvePath(path) orelse return 0;

    if (!ctrl.readSectors(1, dir_lba, 1)) return 0;
    const buf = ctrl.getReadBuf();
    if (buf[0] != INODE_DIR) return 0;

    const block_count = readU32(buf, 80);
    var out_len: usize = 0;

    // Read child LBAs from parent inode's direct_blocks
    // Need to save them since readSectors will overwrite read buffer
    var child_lbas: [INODE_DIRECT_MAX]u32 = undefined;
    var i: u32 = 0;
    while (i < block_count and i < INODE_DIRECT_MAX) : (i += 1) {
        child_lbas[i] = readU32(buf, 84 + i * 4);
    }

    i = 0;
    while (i < block_count and i < INODE_DIRECT_MAX) : (i += 1) {
        if (!ctrl.readSectors(1, child_lbas[i], 1)) continue;
        const child_buf = ctrl.getReadBuf();
        const name_len: usize = @as(usize, child_buf[2]) | (@as(usize, child_buf[3]) << 8);
        const actual_len = @min(name_len, INODE_NAME_MAX);
        if (out_len + actual_len + 1 > out_buf.len) break;
        @memcpy(out_buf[out_len..][0..actual_len], child_buf[4..][0..actual_len]);
        out_len += actual_len;
        out_buf[out_len] = '\n';
        out_len += 1;
    }
    return out_len;
}

pub fn readFile(path: []const u8, out_buf: []u8) usize {
    const inode_lba = resolvePath(path) orelse return 0;

    if (!ctrl.readSectors(1, inode_lba, 1)) return 0;
    const buf = ctrl.getReadBuf();
    if (buf[0] != INODE_FILE) return 0;

    const file_size: usize = @truncate(readU64(buf, 68));
    const block_count = readU32(buf, 80);

    // Save block LBAs
    var data_lbas: [INODE_DIRECT_MAX]u32 = undefined;
    var i: u32 = 0;
    while (i < block_count and i < INODE_DIRECT_MAX) : (i += 1) {
        data_lbas[i] = readU32(buf, 84 + i * 4);
    }

    var out_len: usize = 0;
    i = 0;
    while (i < block_count and i < INODE_DIRECT_MAX) : (i += 1) {
        if (!ctrl.readSectors(1, data_lbas[i], 1)) break;
        const data_buf = ctrl.getReadBuf();
        const remaining = file_size - out_len;
        const chunk = @min(remaining, LBA_SIZE);
        if (out_len + chunk > out_buf.len) break;
        @memcpy(out_buf[out_len..][0..chunk], data_buf[0..chunk]);
        out_len += chunk;
    }
    return out_len;
}

// ── Path resolution ─────────────────────────────────────────────────

fn resolvePath(path: []const u8) ?u32 {
    if (path.len == 0) return null;
    if (path[0] != '/') return null;

    // Root itself
    if (path.len == 1) return ROOT_INODE_LBA;

    var current_lba: u32 = ROOT_INODE_LBA;
    var pos: usize = 1; // skip leading /

    while (pos < path.len) {
        // Skip trailing slashes
        if (path[pos] == '/') {
            pos += 1;
            continue;
        }

        // Extract component
        var end = pos;
        while (end < path.len and path[end] != '/') {
            end += 1;
        }
        const component = path[pos..end];

        // Search current directory for this component
        current_lba = findChild(current_lba, component) orelse return null;
        pos = end;
    }

    return current_lba;
}

fn findChild(dir_lba: u32, name: []const u8) ?u32 {
    if (!ctrl.readSectors(1, dir_lba, 1)) return null;
    const buf = ctrl.getReadBuf();
    if (buf[0] != INODE_DIR) return null;

    const block_count = readU32(buf, 80);

    // Save child LBAs
    var child_lbas: [INODE_DIRECT_MAX]u32 = undefined;
    var i: u32 = 0;
    while (i < block_count and i < INODE_DIRECT_MAX) : (i += 1) {
        child_lbas[i] = readU32(buf, 84 + i * 4);
    }

    i = 0;
    while (i < block_count and i < INODE_DIRECT_MAX) : (i += 1) {
        if (!ctrl.readSectors(1, child_lbas[i], 1)) continue;
        const child_buf = ctrl.getReadBuf();
        const name_len: usize = @as(usize, child_buf[2]) | (@as(usize, child_buf[3]) << 8);
        const actual_len = @min(name_len, INODE_NAME_MAX);
        if (actual_len == name.len and strEql(child_buf[4..][0..actual_len], name)) {
            return child_lbas[i];
        }
    }
    return null;
}

// ── Internal helpers ────────────────────────────────────────────────

fn createEntry(path: []const u8, inode_type: u8) bool {
    if (path.len < 2 or path[0] != '/') return false;

    // Split into parent path and entry name
    var last_slash: usize = 0;
    for (path, 0..) |ch, idx| {
        if (ch == '/') last_slash = idx;
    }
    const parent_path = if (last_slash == 0) "/" else path[0..last_slash];
    const entry_name = path[last_slash + 1 ..];
    if (entry_name.len == 0 or entry_name.len > INODE_NAME_MAX) return false;

    // Resolve parent
    const parent_lba = resolvePath(parent_path) orelse return false;

    // Check parent is a directory
    if (!ctrl.readSectors(1, parent_lba, 1)) return false;
    var rbuf = ctrl.getReadBuf();
    if (rbuf[0] != INODE_DIR) return false;

    // Check name doesn't already exist
    if (findChild(parent_lba, entry_name) != null) return false;

    // Allocate new inode
    const new_lba = allocBlock() orelse return false;

    // Write new inode
    const wbuf = ctrl.getWriteBuf();
    @memset(wbuf[0..LBA_SIZE], 0);
    wbuf[0] = inode_type;
    wbuf[2] = @truncate(entry_name.len);
    wbuf[3] = @truncate(entry_name.len >> 8);
    @memcpy(wbuf[4..][0..entry_name.len], entry_name);
    writeU32(wbuf, 76, parent_lba); // parent
    if (!ctrl.writeSectors(1, new_lba, 1)) return false;

    // Add child to parent's direct_blocks
    if (!ctrl.readSectors(1, parent_lba, 1)) return false;
    rbuf = ctrl.getReadBuf();
    @memcpy(wbuf[0..LBA_SIZE], rbuf[0..LBA_SIZE]);

    const idx = readU32(wbuf, 80); // current block_count
    if (idx >= INODE_DIRECT_MAX) return false;
    writeU32(wbuf, 84 + idx * 4, new_lba);
    writeU32(wbuf, 80, idx + 1);
    if (!ctrl.writeSectors(1, parent_lba, 1)) return false;

    return true;
}

fn removeEntry(path: []const u8, inode_lba: u32) bool {
    if (path.len < 2 or path[0] != '/') return false;

    // Find parent
    var last_slash: usize = 0;
    for (path, 0..) |ch, idx| {
        if (ch == '/') last_slash = idx;
    }
    const parent_path = if (last_slash == 0) "/" else path[0..last_slash];
    const parent_lba = resolvePath(parent_path) orelse return false;

    // Read parent inode
    if (!ctrl.readSectors(1, parent_lba, 1)) return false;
    const rbuf = ctrl.getReadBuf();
    const wbuf = ctrl.getWriteBuf();
    @memcpy(wbuf[0..LBA_SIZE], rbuf[0..LBA_SIZE]);

    // Remove child from parent's direct_blocks
    var block_count = readU32(wbuf, 80);
    var found = false;
    var i: u32 = 0;
    while (i < block_count) : (i += 1) {
        if (readU32(wbuf, 84 + i * 4) == inode_lba) {
            // Swap with last entry
            const last_lba = readU32(wbuf, 84 + (block_count - 1) * 4);
            writeU32(wbuf, 84 + i * 4, last_lba);
            block_count -= 1;
            writeU32(wbuf, 80, block_count);
            found = true;
            break;
        }
    }
    if (!found) return false;
    if (!ctrl.writeSectors(1, parent_lba, 1)) return false;

    // Free inode block
    freeBlock(inode_lba);
    return true;
}

fn allocBlock() ?u32 {
    // Read superblock to get next_free hint
    if (!ctrl.readSectors(1, SUPERBLOCK_LBA, 1)) return null;
    var hint = readU32(ctrl.getReadBuf(), SB_OFF_NEXT_FREE);
    if (hint < FIRST_FREE_LBA) hint = FIRST_FREE_LBA;

    // Scan bitmap for a free block starting from hint
    const bitmap_lba = BITMAP_START + (hint / (LBA_SIZE * 8));
    var scan_lba: u32 = bitmap_lba;
    const total_bits: u32 = BITMAP_LBAS * LBA_SIZE * 8;

    var checked: u32 = 0;
    while (checked < total_bits) {
        if (!ctrl.readSectors(1, BITMAP_START + scan_lba - BITMAP_START, 1)) return null;
        const rbuf = ctrl.getReadBuf();
        const base_bit: u32 = (scan_lba - BITMAP_START) * LBA_SIZE * 8;

        var byte_idx: u32 = 0;
        while (byte_idx < LBA_SIZE) : (byte_idx += 1) {
            if (rbuf[byte_idx] == 0xFF) {
                checked += 8;
                continue;
            }
            var bit: u3 = 0;
            while (true) {
                const block_num = base_bit + byte_idx * 8 + bit;
                if ((rbuf[byte_idx] >> bit) & 1 == 0) {
                    // Found free block — mark it used
                    const wbuf = ctrl.getWriteBuf();
                    @memcpy(wbuf[0..LBA_SIZE], rbuf[0..LBA_SIZE]);
                    setBitmapBit(wbuf, block_num);
                    if (!ctrl.writeSectors(1, BITMAP_START + (scan_lba - BITMAP_START), 1)) return null;

                    // Update superblock hint
                    if (!ctrl.readSectors(1, SUPERBLOCK_LBA, 1)) return null;
                    @memcpy(ctrl.getWriteBuf()[0..LBA_SIZE], ctrl.getReadBuf()[0..LBA_SIZE]);
                    writeU32(ctrl.getWriteBuf(), SB_OFF_NEXT_FREE, block_num + 1);
                    _ = ctrl.writeSectors(1, SUPERBLOCK_LBA, 1);

                    return block_num;
                }
                checked += 1;
                if (bit == 7) break;
                bit += 1;
            }
        }
        scan_lba += 1;
        if (scan_lba >= BITMAP_START + BITMAP_LBAS) {
            scan_lba = BITMAP_START; // wrap around
        }
    }
    return null; // disk full
}

fn freeBlock(lba: u32) void {
    const bitmap_lba = BITMAP_START + lba / (LBA_SIZE * 8);
    if (!ctrl.readSectors(1, bitmap_lba, 1)) return;
    const wbuf = ctrl.getWriteBuf();
    @memcpy(wbuf[0..LBA_SIZE], ctrl.getReadBuf()[0..LBA_SIZE]);
    clearBitmapBit(wbuf, lba);
    _ = ctrl.writeSectors(1, bitmap_lba, 1);
}

fn setBitmapBit(buf: [*]u8, block_num: u32) void {
    const byte_in_bitmap = block_num / 8;
    const bit_in_byte: u3 = @truncate(block_num % 8);
    const lba_offset = byte_in_bitmap % LBA_SIZE;
    buf[lba_offset] |= @as(u8, 1) << bit_in_byte;
}

fn clearBitmapBit(buf: [*]u8, block_num: u32) void {
    const byte_in_bitmap = block_num / 8;
    const bit_in_byte: u3 = @truncate(block_num % 8);
    const lba_offset = byte_in_bitmap % LBA_SIZE;
    buf[lba_offset] &= ~(@as(u8, 1) << bit_in_byte);
}

// ── Byte-level read/write helpers ───────────────────────────────────

fn readU32(buf: [*]const u8, offset: usize) u32 {
    return @as(u32, buf[offset]) |
        (@as(u32, buf[offset + 1]) << 8) |
        (@as(u32, buf[offset + 2]) << 16) |
        (@as(u32, buf[offset + 3]) << 24);
}

fn readU64(buf: [*]const u8, offset: usize) u64 {
    return @as(u64, readU32(buf, offset)) |
        (@as(u64, readU32(buf, offset + 4)) << 32);
}

fn writeU32(buf: [*]u8, offset: usize, val: u32) void {
    buf[offset] = @truncate(val);
    buf[offset + 1] = @truncate(val >> 8);
    buf[offset + 2] = @truncate(val >> 16);
    buf[offset + 3] = @truncate(val >> 24);
}

fn writeU64(buf: [*]u8, offset: usize, val: u64) void {
    writeU32(buf, offset, @truncate(val));
    writeU32(buf, offset + 4, @truncate(val >> 32));
}

fn strEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ac, bc| {
        if (ac != bc) return false;
    }
    return true;
}

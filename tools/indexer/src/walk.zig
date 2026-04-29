const std = @import("std");
const types = @import("types.zig");

const FileRecord = types.FileRecord;
const ModuleRecord = types.ModuleRecord;

pub const WalkResult = struct {
    /// Owns paths, sources, module qnames. Caller deinits.
    arena: std.heap.ArenaAllocator,
    files: []FileRecord,
    modules: []ModuleRecord,
    /// Per-file line start byte offsets. Outer index = file_id.
    line_indices: [][]u32,

    pub fn deinit(self: *WalkResult) void {
        self.arena.deinit();
    }
};

const SKIP_DIRS = [_][]const u8{
    ".git",
    ".zig-cache",
    "zig-cache",
    "zig-out",
    "node_modules",
    "__pycache__",
};

/// Walk `root_dir` recursively, collecting every `.zig` file.
/// Computes file IDs, module IDs, sha256, and line indices.
/// Returned arrays are valid until the WalkResult arena is deinit'd.
pub fn walk(gpa: std.mem.Allocator, root_dir: []const u8) !WalkResult {
    return walkPrefixed(gpa, root_dir, "");
}

/// Like `walk`, but every emitted file `path` and module `qualified_name`
/// is prefixed with `tree_prefix` so multiple non-kernel trees can be
/// merged into one DB without colliding with the kernel's namespace.
/// Pass `""` for the kernel root (no prefix); pass e.g. `"routerOS"` for
/// non-kernel sub-projects.
pub fn walkPrefixed(
    gpa: std.mem.Allocator,
    root_dir: []const u8,
    tree_prefix: []const u8,
) !WalkResult {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    const aalloc = arena.allocator();

    var files: std.ArrayList(FileRecord) = .empty;
    var line_indices: std.ArrayList([]u32) = .empty;
    var modules_by_qname: std.StringHashMap(u32) = std.StringHashMap(u32).init(aalloc);
    var module_records: std.ArrayList(ModuleRecord) = .empty;

    var dir = try std.fs.cwd().openDir(root_dir, .{ .iterate = true });
    defer dir.close();

    var walker = try dir.walk(aalloc);
    defer walker.deinit();

    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        if (!std.mem.endsWith(u8, entry.basename, ".zig")) continue;
        if (shouldSkip(entry.path)) continue;

        // Read file into a sentinel-terminated buffer for parsers.
        const f = try entry.dir.openFile(entry.basename, .{});
        defer f.close();
        const stat = try f.stat();
        if (stat.size > 16 * 1024 * 1024) continue; // skip absurdly large files
        const buf = try aalloc.allocSentinel(u8, @intCast(stat.size), 0);
        const nread = try f.readAll(buf);
        if (nread != stat.size) return error.ShortRead;
        const source: [:0]const u8 = buf;

        // Compute sha256
        var sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(source, &sha, .{});

        // Path relative to root (then prefixed if tree_prefix is non-empty),
        // with `/` separator regardless of OS.
        const rel_path = try aalloc.dupe(u8, entry.path);
        normalizeSlashes(rel_path);
        const path_for_db: []const u8 = if (tree_prefix.len == 0)
            rel_path
        else
            try std.fmt.allocPrint(aalloc, "{s}/{s}", .{ tree_prefix, rel_path });

        // Module qualified name from path. For non-kernel trees we prefix
        // with the tree name so qnames stay globally unique (the `module`
        // table has UNIQUE on qualified_name).
        const module_qname = try deriveModuleQname(aalloc, rel_path, tree_prefix);
        const module_id = try internModule(
            aalloc,
            &modules_by_qname,
            &module_records,
            module_qname,
            @intCast(files.items.len),
        );

        const file_id: u32 = @intCast(files.items.len);
        try files.append(aalloc, .{
            .id = file_id,
            .path = path_for_db,
            .source = source,
            .sha256 = sha,
            .size = @intCast(stat.size),
            .module_id = module_id,
        });

        // Build line index: byte offset of the first character of each line.
        // Line 1 starts at byte 0; subsequent lines start after each '\n'.
        var lines: std.ArrayList(u32) = .empty;
        try lines.append(aalloc, 0);
        for (source, 0..) |ch, i| {
            if (ch == '\n' and i + 1 < source.len) {
                try lines.append(aalloc, @intCast(i + 1));
            }
        }
        try line_indices.append(aalloc, try lines.toOwnedSlice(aalloc));
    }

    return .{
        .arena = arena,
        .files = try files.toOwnedSlice(aalloc),
        .modules = try module_records.toOwnedSlice(aalloc),
        .line_indices = try line_indices.toOwnedSlice(aalloc),
    };
}

fn shouldSkip(path: []const u8) bool {
    var it = std.mem.splitScalar(u8, path, std.fs.path.sep);
    while (it.next()) |seg| {
        for (SKIP_DIRS) |skip| {
            if (std.mem.eql(u8, seg, skip)) return true;
        }
    }
    return false;
}

fn normalizeSlashes(path: []u8) void {
    if (std.fs.path.sep == '/') return;
    for (path) |*c| {
        if (c.* == std.fs.path.sep) c.* = '/';
    }
}

fn deriveModuleQname(
    allocator: std.mem.Allocator,
    rel_path: []const u8,
    tree_prefix: []const u8,
) ![]const u8 {
    // Strip `.zig` suffix, replace `/` with `.`. For non-kernel trees, the
    // resulting stem is prefixed with `<tree_prefix>.` so qnames don't
    // collide with kernel modules of the same shape (e.g. routerOS/build.zig
    // → `routerOS.build` vs kernel `build`).
    const stem = rel_path[0 .. rel_path.len - 4]; // ".zig" is 4 chars
    if (tree_prefix.len == 0) {
        var out = try allocator.alloc(u8, stem.len);
        for (stem, 0..) |c, i| {
            out[i] = if (c == '/') '.' else c;
        }
        return out;
    }
    const total = tree_prefix.len + 1 + stem.len;
    var out = try allocator.alloc(u8, total);
    @memcpy(out[0..tree_prefix.len], tree_prefix);
    out[tree_prefix.len] = '.';
    for (stem, 0..) |c, i| {
        out[tree_prefix.len + 1 + i] = if (c == '/') '.' else c;
    }
    return out;
}

fn internModule(
    allocator: std.mem.Allocator,
    map: *std.StringHashMap(u32),
    records: *std.ArrayList(ModuleRecord),
    qname: []const u8,
    candidate_root_file_id: u32,
) !u32 {
    if (map.get(qname)) |id| return id;
    const id: u32 = @intCast(records.items.len);
    try records.append(allocator, .{
        .id = id,
        .qualified_name = qname,
        .root_file_id = candidate_root_file_id,
    });
    try map.put(qname, id);
    return id;
}

//! Persistent per-commit review state for the callgraph review feature.
//!
//! Storage layout (all under `<git_root>/.callgraph/review/`):
//!   <sha>.json      — channeled review state (mcp + http)
//!   <sha>.mcp.md    — agent's review summary; presence = mcp channel complete
//!   <sha>.http.md   — human's review summary; presence = http channel complete
//!
//! `.callgraph/review/` is the same dir the previous per-hunk-checkbox
//! human-review feature used. The new schema is per-commit (sha-only)
//! and per-symbol; old `<sha_a>..<sha_b>.json` files from that scheme
//! are orphaned, not migrated.
//!
//! Crucial invariant: the `.md` file is the source of truth for "this
//! channel is done". On every load, if a channel's JSON status is
//! `complete` but its `.md` is missing, the channel is reset to null and
//! the JSON is rewritten. Deleting the markdown reopens the review.

const std = @import("std");

pub const ItemKind = enum {
    symbol_signature,
    symbol_body,
    symbol_added,
    symbol_removed,
    type_changed,
    orphan_hunk,

    pub fn jsonStringify(self: ItemKind, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

pub const ChannelStatus = enum {
    in_progress,
    complete,

    pub fn jsonStringify(self: ChannelStatus, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

/// What flavor of deps this item needs viewed. Decided by the classifier
/// at item creation; drives both the deps computer (task #3) and the
/// _checkoff gate (task #5).
///
/// `none` is the gate-bypass marker: orphan hunks and trivial changes
/// have no relevant deps, so _checkoff lets them through without any
/// deps-viewing.
pub const DepsKind = enum {
    none,
    callers,
    callers_callees,
    readers_writers,
    call_sites,
    prior_callers,

    pub fn jsonStringify(self: DepsKind, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

/// One reviewable unit. A changed symbol produces one Item even if the
/// diff splits it into several hunks; orphan hunks (top-level decls,
/// imports, comment blocks) get their own Item.
pub const Item = struct {
    /// Stable id used by gate APIs. Format: `sym:<qualified_name>` or
    /// `hunk:<repo-rel-path>:<start>-<end>`.
    id: []const u8,
    kind: ItemKind,
    /// What deps this item needs viewed. Set by the classifier; drives
    /// both the deps computer and the _checkoff gate.
    deps_kind: DepsKind,
    file: []const u8,
    /// Human-readable line range, e.g. "L120-L145".
    loc: []const u8,
    /// Set for `symbol_*` and `type_changed` items; null for orphans.
    qualified_name: ?[]const u8 = null,
    /// Computed by the classifier at open time so the agent can plan
    /// effort before drilling in (`callers_callees ~12 deps` reads
    /// differently from `callers ~1 dep`). 0 for trivial / none-kind
    /// items. Doesn't satisfy the gate — the agent still has to call
    /// review_deps to populate `deps_required` and then view each.
    deps_count: u32 = 0,
    /// Populated by _deps. `null` means _deps has never been called for
    /// this item. Sticky once written: re-running deps only adds, never
    /// shrinks — prevents agents from "refreshing" to dodge a requirement.
    deps_required: ?[]const []const u8 = null,
    /// Witnessed via callgraph_src / callgraph_trace calls during the
    /// review session. Persists across daemon restarts.
    deps_viewed: []const []const u8 = &.{},
    checked_off: bool = false,
    /// Trivial items (whitespace-only or comment-only orphan hunks)
    /// bypass the deps gate entirely.
    trivial: bool = false,
    notes: ?[]const u8 = null,
};

pub const ChannelState = struct {
    status: ChannelStatus,
    /// Unix seconds.
    started_at: i64,
    completed_at: ?i64 = null,
    /// Set for the `mcp` channel; identifies the agent that ran the
    /// review (e.g. "claude-opus-4-7"). Null for `http`.
    agent_model: ?[]const u8 = null,
    items: []Item = &.{},
    /// Free-text summary written by `_complete`. Mirrored to the `.md`
    /// file, which is the actual source of truth for completion.
    summary: ?[]const u8 = null,
    /// Session-scoped log of every qualified_name the witness has
    /// observed (via `callgraph_src` / `callgraph_type` from this
    /// channel) since `_open`. Used by `_deps` to retro-populate a
    /// freshly-required dep's `deps_viewed` when the agent already
    /// looked at it earlier — fixes the "viewed enqueue under
    /// enqueueOnCore but pickCoreForAffinity still demands it" bug.
    /// Append-only within a session; resets when the channel is
    /// reopened (post-md-deletion or new commit).
    deps_viewed_session: []const []const u8 = &.{},
};

pub const Channels = struct {
    mcp: ?ChannelState = null,
    http: ?ChannelState = null,
};

pub const ReviewState = struct {
    schema_version: u32 = 1,
    sha: []const u8,
    /// First line of the commit message. Cached at `_open` time so the
    /// commit-list query doesn't have to shell out to `git`.
    subject: []const u8,
    channels: Channels = .{},
};

pub const Channel = enum {
    mcp,
    http,

    pub fn tag(self: Channel) []const u8 {
        return @tagName(self);
    }
};

pub const SummaryPresence = struct {
    mcp: bool,
    http: bool,
};

pub const Store = struct {
    git_root: []const u8,

    pub fn init(git_root: []const u8) Store {
        return .{ .git_root = git_root };
    }

    fn dirPath(self: Store, alloc: std.mem.Allocator) ![]u8 {
        return std.fs.path.join(alloc, &.{ self.git_root, ".callgraph", "review" });
    }

    pub fn stateFilePath(self: Store, alloc: std.mem.Allocator, sha: []const u8) ![]u8 {
        const dir = try self.dirPath(alloc);
        defer alloc.free(dir);
        return std.fmt.allocPrint(alloc, "{s}/{s}.json", .{ dir, sha });
    }

    pub fn summaryFilePath(
        self: Store,
        alloc: std.mem.Allocator,
        sha: []const u8,
        channel: Channel,
    ) ![]u8 {
        const dir = try self.dirPath(alloc);
        defer alloc.free(dir);
        return std.fmt.allocPrint(alloc, "{s}/{s}.{s}.md", .{ dir, sha, channel.tag() });
    }

    /// Load review state for `sha`. Returns null if no JSON file exists.
    /// Performs the channel-reset-on-md-deletion check: if a channel's
    /// stored status is `complete` but its `.md` file is missing, that
    /// channel is reset to null and the JSON is rewritten.
    ///
    /// Returned strings live in `alloc` — the caller should scope it
    /// (typically an arena) to the request handling the load.
    pub fn load(
        self: Store,
        alloc: std.mem.Allocator,
        sha: []const u8,
    ) !?ReviewState {
        const file_path = try self.stateFilePath(alloc, sha);
        defer alloc.free(file_path);

        // Don't defer-free: parseFromSliceLeaky may return string slices
        // that point into `bytes` when no JSON escape sequences are
        // present. The caller's `alloc` (typically an arena) owns both.
        const bytes = std.fs.cwd().readFileAlloc(alloc, file_path, 32 * 1024 * 1024) catch |err| switch (err) {
            error.FileNotFound => return null,
            else => return err,
        };

        var state = std.json.parseFromSliceLeaky(ReviewState, alloc, bytes, .{
            .ignore_unknown_fields = true,
        }) catch return error.CorruptReviewState;

        var changed = false;
        if (state.channels.mcp) |ch| {
            if (ch.status == .complete and !try self.summaryExists(alloc, sha, .mcp)) {
                state.channels.mcp = null;
                changed = true;
            }
        }
        if (state.channels.http) |ch| {
            if (ch.status == .complete and !try self.summaryExists(alloc, sha, .http)) {
                state.channels.http = null;
                changed = true;
            }
        }
        if (changed) try self.save(alloc, &state);
        return state;
    }

    /// Atomically write `state` to disk. Creates the cg-reviews directory
    /// if needed.
    pub fn save(
        self: Store,
        alloc: std.mem.Allocator,
        state: *const ReviewState,
    ) !void {
        const dir_path = try self.dirPath(alloc);
        defer alloc.free(dir_path);
        std.fs.cwd().makePath(dir_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const file_path = try self.stateFilePath(alloc, state.sha);
        defer alloc.free(file_path);
        const tmp_path = try std.fmt.allocPrint(alloc, "{s}.tmp", .{file_path});
        defer alloc.free(tmp_path);

        const blob = try std.json.Stringify.valueAlloc(alloc, state.*, .{ .whitespace = .indent_2 });
        defer alloc.free(blob);

        {
            const f = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
            defer f.close();
            try f.writeAll(blob);
        }
        try std.fs.cwd().rename(tmp_path, file_path);
    }

    /// Atomically write a channel's `.md` summary. Writing this file is
    /// what flips a channel from in_progress to "really complete" — the
    /// `_complete` MCP call must call this *after* updating the JSON to
    /// `status = complete`.
    pub fn writeSummary(
        self: Store,
        alloc: std.mem.Allocator,
        sha: []const u8,
        channel: Channel,
        content: []const u8,
    ) !void {
        const dir_path = try self.dirPath(alloc);
        defer alloc.free(dir_path);
        std.fs.cwd().makePath(dir_path) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };

        const file_path = try self.summaryFilePath(alloc, sha, channel);
        defer alloc.free(file_path);
        const tmp_path = try std.fmt.allocPrint(alloc, "{s}.tmp", .{file_path});
        defer alloc.free(tmp_path);

        {
            const f = try std.fs.cwd().createFile(tmp_path, .{ .truncate = true });
            defer f.close();
            try f.writeAll(content);
        }
        try std.fs.cwd().rename(tmp_path, file_path);
    }

    /// Read a channel's `.md` summary back. Returns null if missing.
    pub fn readSummary(
        self: Store,
        alloc: std.mem.Allocator,
        sha: []const u8,
        channel: Channel,
    ) !?[]u8 {
        const file_path = try self.summaryFilePath(alloc, sha, channel);
        defer alloc.free(file_path);
        return std.fs.cwd().readFileAlloc(alloc, file_path, 8 * 1024 * 1024) catch |err| switch (err) {
            error.FileNotFound => null,
            else => err,
        };
    }

    fn summaryExists(
        self: Store,
        alloc: std.mem.Allocator,
        sha: []const u8,
        channel: Channel,
    ) !bool {
        const file_path = try self.summaryFilePath(alloc, sha, channel);
        defer alloc.free(file_path);
        std.fs.cwd().access(file_path, .{}) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
    }

    /// Cheap stat-only check used by the commit-list badges. Does not
    /// load the JSON. Two stats per call.
    pub fn summariesPresent(
        self: Store,
        alloc: std.mem.Allocator,
        sha: []const u8,
    ) !SummaryPresence {
        return .{
            .mcp = try self.summaryExists(alloc, sha, .mcp),
            .http = try self.summaryExists(alloc, sha, .http),
        };
    }

    /// Enumerate every `<sha>.json` in the cg-reviews dir. Returns shas
    /// only — the caller can `load(sha)` per-entry if they need state.
    /// Returned slice and inner strings are allocated in `alloc`.
    pub fn listShas(self: Store, alloc: std.mem.Allocator) ![][]const u8 {
        const dir_path = try self.dirPath(alloc);
        defer alloc.free(dir_path);

        var dir = std.fs.cwd().openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound => return alloc.alloc([]const u8, 0),
            else => return err,
        };
        defer dir.close();

        var out = std.ArrayList([]const u8){};
        defer out.deinit(alloc);

        var it = dir.iterate();
        while (try it.next()) |entry| {
            if (entry.kind != .file) continue;
            if (!std.mem.endsWith(u8, entry.name, ".json")) continue;
            // Skip atomic-write temporaries.
            if (std.mem.endsWith(u8, entry.name, ".json.tmp")) continue;
            // Skip the legacy per-pair-comparison files
            // (`<sha_a>..<sha_b>.json`) the old per-hunk-checkbox feature
            // wrote into the same dir. They use a different schema and
            // would error as CorruptReviewState every time the witness
            // pass touches them.
            if (std.mem.indexOfScalar(u8, entry.name, '.') != null and
                std.mem.indexOf(u8, entry.name, "..") != null) continue;
            const sha = entry.name[0 .. entry.name.len - ".json".len];
            try out.append(alloc, try alloc.dupe(u8, sha));
        }
        return try out.toOwnedSlice(alloc);
    }
};

// ---- Tests ---------------------------------------------------------------

const testing = std.testing;

/// Builds a Store rooted at a fresh tmp dir whose layout mimics a real
/// repo: `<root>/.git/` exists, so `Store.dirPath` resolves to a
/// writable path. Returns the tmp dir (caller must `cleanup()`) and a
/// Store whose `git_root` outlives the test scope.
fn tmpStore(alloc: std.mem.Allocator) !struct {
    tmp: std.testing.TmpDir,
    git_root: []u8,
    store: Store,
} {
    var tmp = std.testing.tmpDir(.{});
    errdefer tmp.cleanup();
    const git_root = try tmp.dir.realpathAlloc(alloc, ".");
    return .{
        .tmp = tmp,
        .git_root = git_root,
        .store = Store.init(git_root),
    };
}

test "Store: load returns null when no state file" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();

    const got = try ts.store.load(arena.allocator(), "abcdef1234567890");
    try testing.expect(got == null);
}

test "Store: save then load round-trips" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    const items = try aalloc.dupe(Item, &.{
        .{
            .id = "sym:foo.bar",
            .kind = .symbol_body,
            .deps_kind = .callers,
            .file = "src/foo.zig",
            .loc = "L10-L20",
            .qualified_name = "foo.bar",
            .deps_required = try aalloc.dupe([]const u8, &.{ "foo.callerOne", "foo.callerTwo" }),
            .deps_viewed = try aalloc.dupe([]const u8, &.{"foo.callerOne"}),
            .checked_off = false,
            .trivial = false,
            .notes = null,
        },
        .{
            .id = "hunk:src/foo.zig:1-3",
            .kind = .orphan_hunk,
            .deps_kind = .none,
            .file = "src/foo.zig",
            .loc = "L1-L3",
            .qualified_name = null,
            .checked_off = true,
            .trivial = true,
        },
    });

    const original = ReviewState{
        .sha = "deadbeef0001",
        .subject = "test commit",
        .channels = .{
            .mcp = .{
                .status = .in_progress,
                .started_at = 1700000000,
                .agent_model = "claude-opus-4-7",
                .items = items,
            },
        },
    };

    try ts.store.save(aalloc, &original);

    const loaded = (try ts.store.load(aalloc, original.sha)) orelse return error.MissingState;
    try testing.expectEqualStrings(original.sha, loaded.sha);
    try testing.expectEqualStrings(original.subject, loaded.subject);
    try testing.expect(loaded.channels.mcp != null);
    try testing.expect(loaded.channels.http == null);
    const mcp = loaded.channels.mcp.?;
    try testing.expect(mcp.status == .in_progress);
    try testing.expectEqual(@as(i64, 1700000000), mcp.started_at);
    try testing.expectEqualStrings("claude-opus-4-7", mcp.agent_model.?);
    try testing.expectEqual(@as(usize, 2), mcp.items.len);

    try testing.expectEqualStrings("sym:foo.bar", mcp.items[0].id);
    try testing.expect(mcp.items[0].kind == .symbol_body);
    try testing.expect(mcp.items[0].deps_kind == .callers);
    try testing.expect(mcp.items[0].deps_required != null);
    try testing.expectEqual(@as(usize, 2), mcp.items[0].deps_required.?.len);
    try testing.expectEqualStrings("foo.callerOne", mcp.items[0].deps_required.?[0]);
    try testing.expectEqual(@as(usize, 1), mcp.items[0].deps_viewed.len);
    try testing.expect(!mcp.items[0].checked_off);

    try testing.expect(mcp.items[1].kind == .orphan_hunk);
    try testing.expect(mcp.items[1].deps_kind == .none);
    try testing.expect(mcp.items[1].trivial);
    try testing.expect(mcp.items[1].checked_off);
    try testing.expect(mcp.items[1].qualified_name == null);
    try testing.expect(mcp.items[1].deps_required == null);
}

test "Store: complete channel resets when md is missing on next load" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    const sha = "cafef00d0001";
    var state = ReviewState{
        .sha = sha,
        .subject = "another test commit",
        .channels = .{
            .mcp = .{
                .status = .complete,
                .started_at = 1700000000,
                .completed_at = 1700001000,
                .agent_model = "claude-opus-4-7",
                .items = &.{},
                .summary = "all done",
            },
            .http = .{
                .status = .complete,
                .started_at = 1700002000,
                .completed_at = 1700003000,
                .items = &.{},
                .summary = "lgtm",
            },
        },
    };

    try ts.store.save(aalloc, &state);

    // Write only the http .md — leave mcp summary missing.
    try ts.store.writeSummary(aalloc, sha, .http, "lgtm");

    // First load: mcp gets reset (no md), http stays complete.
    const loaded = (try ts.store.load(aalloc, sha)) orelse return error.MissingState;
    try testing.expect(loaded.channels.mcp == null);
    try testing.expect(loaded.channels.http != null);
    try testing.expect(loaded.channels.http.?.status == .complete);

    // The reset should also have been persisted — re-load should match.
    const reloaded = (try ts.store.load(aalloc, sha)) orelse return error.MissingState;
    try testing.expect(reloaded.channels.mcp == null);
    try testing.expect(reloaded.channels.http != null);

    // Now delete the http md too.
    {
        const md_path = try ts.store.summaryFilePath(aalloc, sha, .http);
        try std.fs.cwd().deleteFile(md_path);
    }
    const after = (try ts.store.load(aalloc, sha)) orelse return error.MissingState;
    try testing.expect(after.channels.mcp == null);
    try testing.expect(after.channels.http == null);
}

test "Store: in_progress channels never trigger md-reset" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    const sha = "feedface0001";
    const original = ReviewState{
        .sha = sha,
        .subject = "in-progress test",
        .channels = .{
            .mcp = .{
                .status = .in_progress,
                .started_at = 1700000000,
                .agent_model = "claude-opus-4-7",
                .items = &.{},
            },
        },
    };
    try ts.store.save(aalloc, &original);

    const loaded = (try ts.store.load(aalloc, sha)) orelse return error.MissingState;
    try testing.expect(loaded.channels.mcp != null);
    try testing.expect(loaded.channels.mcp.?.status == .in_progress);
}

test "Store: summariesPresent reflects on-disk state" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    const sha = "1234567890ab";
    const empty = try ts.store.summariesPresent(aalloc, sha);
    try testing.expect(!empty.mcp);
    try testing.expect(!empty.http);

    try ts.store.writeSummary(aalloc, sha, .mcp, "agent summary");
    const after_mcp = try ts.store.summariesPresent(aalloc, sha);
    try testing.expect(after_mcp.mcp);
    try testing.expect(!after_mcp.http);

    try ts.store.writeSummary(aalloc, sha, .http, "human summary");
    const both = try ts.store.summariesPresent(aalloc, sha);
    try testing.expect(both.mcp);
    try testing.expect(both.http);
}

test "Store: readSummary returns content and null when missing" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    const sha = "abcd00112233";
    try testing.expect((try ts.store.readSummary(aalloc, sha, .mcp)) == null);

    try ts.store.writeSummary(aalloc, sha, .mcp, "# Review\n\nlooked at it\n");
    const got = (try ts.store.readSummary(aalloc, sha, .mcp)) orelse return error.MissingSummary;
    try testing.expectEqualStrings("# Review\n\nlooked at it\n", got);
}

test "Store: listShas finds saved commits and skips non-json files" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    const empty = try ts.store.listShas(aalloc);
    try testing.expectEqual(@as(usize, 0), empty.len);

    const shas = [_][]const u8{ "aaaa00000001", "bbbb00000002", "cccc00000003" };
    for (shas) |sha| {
        const state = ReviewState{
            .sha = sha,
            .subject = "list test",
            .channels = .{},
        };
        try ts.store.save(aalloc, &state);
        // Drop a co-resident .md to make sure listShas ignores it.
        try ts.store.writeSummary(aalloc, sha, .mcp, "n/a");
    }

    const found = try ts.store.listShas(aalloc);
    try testing.expectEqual(shas.len, found.len);

    var seen = [_]bool{ false, false, false };
    for (found) |entry| {
        for (shas, 0..) |expected, i| {
            if (std.mem.eql(u8, entry, expected)) seen[i] = true;
        }
    }
    for (seen) |s| try testing.expect(s);
}

test "Store: save overwrites prior state" {
    var ts = try tmpStore(testing.allocator);
    defer ts.tmp.cleanup();
    defer testing.allocator.free(ts.git_root);

    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const aalloc = arena.allocator();

    const sha = "999900001111";
    const v1 = ReviewState{
        .sha = sha,
        .subject = "first",
        .channels = .{
            .mcp = .{
                .status = .in_progress,
                .started_at = 1,
                .agent_model = "claude-opus-4-7",
                .items = &.{},
            },
        },
    };
    try ts.store.save(aalloc, &v1);

    const v2 = ReviewState{
        .sha = sha,
        .subject = "second",
        .channels = .{
            .mcp = .{
                .status = .in_progress,
                .started_at = 2,
                .agent_model = "claude-opus-4-7",
                .items = &.{},
            },
        },
    };
    try ts.store.save(aalloc, &v2);

    const loaded = (try ts.store.load(aalloc, sha)) orelse return error.MissingState;
    try testing.expectEqualStrings("second", loaded.subject);
    try testing.expectEqual(@as(i64, 2), loaded.channels.mcp.?.started_at);
}

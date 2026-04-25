//! Per-commit graph loading.
//!
//! Manages git worktrees, runs builds, and parses the resulting IR to
//! produce per-arch graphs for arbitrary commits. State is owned per-sha
//! in a thread-safe registry. Builds run on a dedicated worker thread so
//! the accept loop is never blocked.
//!
//! Lifecycle for a sha:
//!   1. POST /api/load_commit?sha=X transitions not_loaded → building and
//!      spawns a worker.
//!   2. Worker creates worktree, runs `zig build -Demit_ir=true` per arch,
//!      walks AST, parses IR, builds Graph, serializes JSON blobs.
//!   3. On success: ready, blobs available via /api/graph?sha=X&arch=A.
//!   4. On failure: errored, with a short error_msg.
//!
//! Per-sha entries persist for the life of the server. Worktrees on disk
//! are reused across server restarts.

const std = @import("std");

const ast = @import("ast/index.zig");
const def_deps = @import("def_deps.zig");
const entry_mod = @import("entry.zig");
const ir = @import("ir/parse.zig");
const join = @import("join.zig");
const reachability = @import("reachability.zig");
const types = @import("types.zig");

const Graph = types.Graph;

pub const ArchSpec = struct {
    /// Tag passed to root build.zig (`-Darch=`).
    build_tag: []const u8,
    /// Filename suffix produced by root build.zig.
    file_tag: []const u8,
    /// Frontend-facing tag.
    api_tag: []const u8,
    target_arch: types.TargetArch,
};

pub const Status = enum {
    not_loaded,
    building,
    ready,
    errored,

    pub fn jsonStringify(self: Status, jw: anytype) !void {
        try jw.write(@tagName(self));
    }
};

/// One loaded commit. Owns its arena (graph data) and gpa-allocated
/// blobs (per-arch JSON, plus the `arches` blob).
pub const Entry = struct {
    sha: []u8,
    short_sha: []u8,
    /// Absolute worktree path (e.g. /var/tmp/cg-worktrees/<sha>).
    worktree_path: []u8,
    /// Per-arch serialized graph JSON, keyed by api_tag.
    arch_blobs: std.StringHashMap([]u8),
    /// Pre-serialized `/api/arches` payload for this commit.
    arches_blob: []u8,
    /// Loaded arches in deterministic order; backs `arches_blob`.
    arches: std.ArrayList([]const u8),
    /// Default arch tag (must be a key in `arch_blobs`).
    default_arch: []u8,
    status: Status,
    /// Short, human-readable error description on failure. Owned by gpa.
    error_msg: ?[]u8,
    /// Holds the per-commit Graph + interned strings. Boxed so the
    /// allocator can outlive the Entry's location across map reallocs.
    arena: *std.heap.ArenaAllocator,
};

pub const Registry = struct {
    gpa: std.mem.Allocator,
    git_root: []const u8,
    worktree_dir: []const u8,
    arch_specs: []const ArchSpec,

    mutex: std.Thread.Mutex = .{},
    /// sha -> *Entry. Pointers are stable: entries are never moved or
    /// freed. Map can grow under the mutex.
    entries: std.StringHashMap(*Entry),

    pub fn init(
        gpa: std.mem.Allocator,
        git_root: []const u8,
        worktree_dir: []const u8,
        arch_specs: []const ArchSpec,
    ) Registry {
        return .{
            .gpa = gpa,
            .git_root = git_root,
            .worktree_dir = worktree_dir,
            .arch_specs = arch_specs,
            .entries = std.StringHashMap(*Entry).init(gpa),
        };
    }

    /// Look up an entry by sha. Returns null if no load has been requested.
    /// Caller must NOT mutate; pointer is stable but inner status field
    /// may be racing with a worker thread. Hold `lockShared()` if you need
    /// a consistent snapshot of multiple fields.
    pub fn get(self: *Registry, sha: []const u8) ?*Entry {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.entries.get(sha);
    }

    pub fn lockShared(self: *Registry) void {
        self.mutex.lock();
    }

    pub fn unlockShared(self: *Registry) void {
        self.mutex.unlock();
    }

    /// Triggers a load for `sha` if one isn't already in flight. Returns
    /// the entry pointer, with status reflecting current state. Does not
    /// block on the build.
    pub fn requestLoad(self: *Registry, sha: []const u8) !*Entry {
        self.mutex.lock();

        if (self.entries.get(sha)) |existing| {
            self.mutex.unlock();
            return existing;
        }

        // Reserve a slot. Allocate everything outside the mutex if we
        // need to release for any reason — but here we hold across the
        // small allocs and the put.
        const sha_owned = try self.gpa.dupe(u8, sha);
        errdefer self.gpa.free(sha_owned);

        const arena = try self.gpa.create(std.heap.ArenaAllocator);
        errdefer self.gpa.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(self.gpa);
        errdefer arena.deinit();

        const entry_ptr = try self.gpa.create(Entry);
        errdefer self.gpa.destroy(entry_ptr);

        entry_ptr.* = .{
            .sha = sha_owned,
            .short_sha = try self.gpa.dupe(u8, sha[0..@min(sha.len, 12)]),
            .worktree_path = try std.fs.path.join(self.gpa, &.{ self.worktree_dir, sha_owned }),
            .arch_blobs = std.StringHashMap([]u8).init(self.gpa),
            .arches_blob = try self.gpa.dupe(u8, "{\"arches\":[],\"default\":\"\"}"),
            .arches = std.ArrayList([]const u8){},
            .default_arch = try self.gpa.dupe(u8, ""),
            .status = .building,
            .error_msg = null,
            .arena = arena,
        };

        try self.entries.put(sha_owned, entry_ptr);
        self.mutex.unlock();

        // Spawn the worker. It owns the build pipeline; on completion it
        // updates entry_ptr fields under the mutex.
        const ctx = try self.gpa.create(WorkerCtx);
        ctx.* = .{ .registry = self, .entry = entry_ptr };
        const t = std.Thread.spawn(.{}, workerMain, .{ctx}) catch |err| {
            // Failed to spawn — record error directly. Hold the mutex
            // so observers see a consistent state.
            self.gpa.destroy(ctx);
            self.mutex.lock();
            entry_ptr.status = .errored;
            entry_ptr.error_msg = std.fmt.allocPrint(
                self.gpa,
                "failed to spawn worker: {s}",
                .{@errorName(err)},
            ) catch null;
            self.mutex.unlock();
            return entry_ptr;
        };
        t.detach();

        return entry_ptr;
    }
};

const WorkerCtx = struct {
    registry: *Registry,
    entry: *Entry,
};

fn workerMain(ctx: *WorkerCtx) void {
    const reg = ctx.registry;
    const entry = ctx.entry;
    defer reg.gpa.destroy(ctx);

    runLoad(reg, entry) catch |err| {
        reg.mutex.lock();
        defer reg.mutex.unlock();
        entry.status = .errored;
        if (entry.error_msg == null) {
            entry.error_msg = std.fmt.allocPrint(
                reg.gpa,
                "load failed: {s}",
                .{@errorName(err)},
            ) catch null;
        }
        return;
    };
}

fn runLoad(reg: *Registry, entry: *Entry) !void {
    // 1. Ensure worktree exists.
    try ensureWorktree(reg.gpa, reg.git_root, entry);

    // 2. Build per arch — best effort. If at least one arch succeeds we
    //    treat the load as ready.
    const kernel_root_in_worktree = try std.fs.path.join(
        reg.gpa,
        &.{ entry.worktree_path, "kernel" },
    );
    defer reg.gpa.free(kernel_root_in_worktree);

    const ir_dir_in_worktree = try std.fs.path.join(
        reg.gpa,
        &.{ entry.worktree_path, "zig-out" },
    );
    defer reg.gpa.free(ir_dir_in_worktree);

    for (reg.arch_specs) |spec| {
        buildOneArch(reg.gpa, entry.worktree_path, spec) catch |err| {
            std.debug.print(
                "[commit {s}] build {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            // Continue to next arch — partial success is acceptable.
            continue;
        };
    }

    // 3. AST walk — once per worktree, shared across arches.
    const arena_alloc = entry.arena.allocator();
    const walk = ast.walkKernelFull(arena_alloc, kernel_root_in_worktree) catch |err| {
        const msg = try std.fmt.allocPrint(
            reg.gpa,
            "AST walk failed: {s}",
            .{@errorName(err)},
        );
        reg.mutex.lock();
        entry.error_msg = msg;
        entry.status = .errored;
        reg.mutex.unlock();
        return;
    };

    // 4. Per-arch parse + join + reach.
    for (reg.arch_specs) |spec| {
        const ir_filename = try std.fmt.allocPrint(
            reg.gpa,
            "kernel.{s}.ll",
            .{spec.file_tag},
        );
        defer reg.gpa.free(ir_filename);

        const ir_path = try std.fs.path.join(reg.gpa, &.{ ir_dir_in_worktree, ir_filename });
        defer reg.gpa.free(ir_path);

        std.fs.cwd().access(ir_path, .{}) catch {
            std.debug.print(
                "[commit {s}] no IR at {s}; skipping arch\n",
                .{ entry.short_sha, ir_path },
            );
            continue;
        };

        // The IR parse must share the commit's arena: buildGraphWithStats
        // keeps references to mangled names and SourceLocs allocated by
        // ir.parse, so a separate arena would leave dangling slices once
        // it deinits. Memory grows with the IR size but caps at one
        // commit's worth — acceptable.
        const ir_graph = ir.parse(entry.arena, ir_path) catch |err| {
            std.debug.print(
                "[commit {s}] IR parse {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            continue;
        };

        const discovered = entry_mod.discover(
            arena_alloc,
            kernel_root_in_worktree,
            spec.build_tag,
            walk.fns,
            walk.asts,
        ) catch |err| {
            std.debug.print(
                "[commit {s}] entry.discover {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            continue;
        };

        var stats: join.JoinStats = undefined;
        var graph = join.buildGraphWithStats(
            arena_alloc,
            ir_graph,
            walk.fns,
            walk.asts,
            walk.struct_types,
            walk.aliases,
            discovered,
            spec.target_arch,
            &stats,
        ) catch |err| {
            std.debug.print(
                "[commit {s}] join {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            continue;
        };

        // Mirror main.zig: install the Definition catalog and dep edges
        // for this commit's snapshot.
        graph.definitions = ast.buildDefinitionList(arena_alloc, walk.definitions) catch &.{};
        def_deps.compute(arena_alloc, &graph, walk.asts, walk.aliases) catch |err| {
            std.debug.print(
                "[commit {s}] def_deps {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
        };

        _ = reachability.compute(reg.gpa, &graph) catch {};

        const blob = std.json.Stringify.valueAlloc(reg.gpa, graph, .{}) catch |err| {
            std.debug.print(
                "[commit {s}] serialize {s} failed: {s}\n",
                .{ entry.short_sha, spec.api_tag, @errorName(err) },
            );
            continue;
        };

        // Install under mutex.
        reg.mutex.lock();
        const dup_key = reg.gpa.dupe(u8, spec.api_tag) catch {
            reg.gpa.free(blob);
            reg.mutex.unlock();
            continue;
        };
        entry.arch_blobs.put(dup_key, blob) catch {
            reg.gpa.free(dup_key);
            reg.gpa.free(blob);
        };
        entry.arches.append(reg.gpa, dup_key) catch {};
        reg.mutex.unlock();

        std.debug.print(
            "[commit {s}] arch {s} ready ({d} fns)\n",
            .{ entry.short_sha, spec.api_tag, graph.functions.len },
        );
    }

    // 5. Finalize: build arches_blob + status.
    reg.mutex.lock();
    defer reg.mutex.unlock();

    if (entry.arches.items.len == 0) {
        entry.status = .errored;
        if (entry.error_msg == null) {
            entry.error_msg = try reg.gpa.dupe(u8, "no arches built successfully");
        }
        return;
    }

    // Pick default: prefer x86_64.
    var default_idx: usize = 0;
    for (entry.arches.items, 0..) |a, i| {
        if (std.mem.eql(u8, a, "x86_64")) {
            default_idx = i;
            break;
        }
    }
    reg.gpa.free(entry.default_arch);
    entry.default_arch = try reg.gpa.dupe(u8, entry.arches.items[default_idx]);

    var buf = std.ArrayList(u8){};
    defer buf.deinit(reg.gpa);
    try buf.appendSlice(reg.gpa, "{\"arches\":[");
    for (entry.arches.items, 0..) |a, i| {
        if (i > 0) try buf.append(reg.gpa, ',');
        try buf.append(reg.gpa, '"');
        try buf.appendSlice(reg.gpa, a);
        try buf.append(reg.gpa, '"');
    }
    try buf.appendSlice(reg.gpa, "],\"default\":\"");
    try buf.appendSlice(reg.gpa, entry.default_arch);
    try buf.appendSlice(reg.gpa, "\"}");

    reg.gpa.free(entry.arches_blob);
    entry.arches_blob = try buf.toOwnedSlice(reg.gpa);
    entry.status = .ready;
}

fn ensureWorktree(
    gpa: std.mem.Allocator,
    git_root: []const u8,
    entry: *Entry,
) !void {
    // Make parent dir.
    const parent = std.fs.path.dirname(entry.worktree_path) orelse return error.InvalidWorktreePath;
    std.fs.cwd().makePath(parent) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    // If worktree already exists with the right sha, reuse it.
    if (std.fs.cwd().access(entry.worktree_path, .{})) |_| {
        // Validate: HEAD inside this worktree should resolve to entry.sha.
        const head_ok = checkWorktreeHead(gpa, entry.worktree_path, entry.sha) catch false;
        if (head_ok) return;
        // Stale worktree — remove and recreate.
        try removeWorktree(gpa, git_root, entry.worktree_path);
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }

    // Prune any stale worktree registrations before adding. Without this,
    // a worktree dir that was deleted out-of-band leaves a phantom entry
    // in `.git/worktrees/`, and `git worktree add` refuses to reuse the
    // same path.
    pruneWorktrees(gpa, git_root);

    // git worktree add --detach <path> <sha>
    const argv = [_][]const u8{
        "git",         "worktree", "add", "--detach",
        entry.worktree_path,
        entry.sha,
    };
    const result = try std.process.Child.run(.{
        .allocator = gpa,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 256 * 1024,
    });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) {
            std.debug.print(
                "git worktree add failed (code {d}): {s}\n",
                .{ code, result.stderr },
            );
            return error.WorktreeAddFailed;
        },
        else => return error.WorktreeAddFailed,
    }
}

fn pruneWorktrees(gpa: std.mem.Allocator, git_root: []const u8) void {
    const argv = [_][]const u8{ "git", "worktree", "prune" };
    const result = std.process.Child.run(.{
        .allocator = gpa,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 64 * 1024,
    }) catch return;
    gpa.free(result.stdout);
    gpa.free(result.stderr);
}

fn checkWorktreeHead(
    gpa: std.mem.Allocator,
    worktree_path: []const u8,
    expected_sha: []const u8,
) !bool {
    const argv = [_][]const u8{ "git", "rev-parse", "HEAD" };
    const result = std.process.Child.run(.{
        .allocator = gpa,
        .argv = &argv,
        .cwd = worktree_path,
        .max_output_bytes = 4096,
    }) catch return false;
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    switch (result.term) {
        .Exited => |code| if (code != 0) return false,
        else => return false,
    }
    const trimmed = std.mem.trim(u8, result.stdout, "\n\r \t");
    return std.mem.eql(u8, trimmed, expected_sha);
}

fn removeWorktree(
    gpa: std.mem.Allocator,
    git_root: []const u8,
    worktree_path: []const u8,
) !void {
    const argv = [_][]const u8{ "git", "worktree", "remove", "--force", worktree_path };
    const result = std.process.Child.run(.{
        .allocator = gpa,
        .argv = &argv,
        .cwd = git_root,
        .max_output_bytes = 64 * 1024,
    }) catch {
        // Fall back to rm -rf if git refuses (e.g. worktree was deleted
        // outside of git already and `prune` hasn't run).
        try std.fs.cwd().deleteTree(worktree_path);
        return;
    };
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    // Ignore exit code — failures are typical (e.g. already-pruned).
    _ = result.term;

    // Best-effort cleanup if dir lingered.
    std.fs.cwd().deleteTree(worktree_path) catch {};
}

fn buildOneArch(
    gpa: std.mem.Allocator,
    worktree_path: []const u8,
    spec: ArchSpec,
) !void {
    const arch_arg = try std.fmt.allocPrint(gpa, "-Darch={s}", .{spec.build_tag});
    defer gpa.free(arch_arg);

    const argv = [_][]const u8{
        "zig",
        "build",
        "-Dprofile=test",
        "-Demit_ir=true",
        arch_arg,
    };

    std.debug.print(
        "[commit] running build in {s}: zig build -Dprofile=test -Demit_ir=true {s}\n",
        .{ worktree_path, arch_arg },
    );

    var child = std.process.Child.init(&argv, gpa);
    child.cwd = worktree_path;
    child.stdout_behavior = .Inherit;
    child.stderr_behavior = .Inherit;
    try child.spawn();
    const term = try child.wait();
    switch (term) {
        .Exited => |code| if (code != 0) return error.BuildFailed,
        else => return error.BuildFailed,
    }
}

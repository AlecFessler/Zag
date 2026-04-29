const std = @import("std");
const types = @import("types.zig");
const writer = @import("writer.zig");

const ProvisionalEntity = types.ProvisionalEntity;
const FinalEntity = writer.FinalEntity;
const AstEntityRef = writer.AstEntityRef;

pub const ResolveResult = struct {
    final_entities: []FinalEntity,
    ast_backfill: []AstEntityRef,
};

/// Stage 2.5 — single-threaded entity-id resolution.
///
/// Takes provisional entities from all per-file workers, sorts by
/// (module_id, kind, qualified_name), deduplicates exact triple collisions,
/// assigns sequential entity IDs, and produces the ast_node entity_id
/// back-fill list so the writer can UPDATE ast_node rows after entities are
/// inserted.
pub fn resolve(
    allocator: std.mem.Allocator,
    provisional: []const ProvisionalEntity,
) !ResolveResult {
    const indices = try allocator.alloc(u32, provisional.len);
    defer allocator.free(indices);
    for (indices, 0..) |*idx, i| idx.* = @intCast(i);

    const Ctx = struct {
        prov: []const ProvisionalEntity,
        fn lessThan(self: @This(), a: u32, b: u32) bool {
            const x = self.prov[a];
            const y = self.prov[b];
            if (x.module_id != y.module_id) return x.module_id < y.module_id;
            const kx = @intFromEnum(x.kind);
            const ky = @intFromEnum(y.kind);
            if (kx != ky) return kx < ky;
            return std.mem.lessThan(u8, x.qualified_name, y.qualified_name);
        }
    };
    std.mem.sort(u32, indices, Ctx{ .prov = provisional }, Ctx.lessThan);

    var entities_out: std.ArrayList(FinalEntity) = .empty;
    try entities_out.ensureTotalCapacity(allocator, provisional.len);
    var backfill_out: std.ArrayList(AstEntityRef) = .empty;
    try backfill_out.ensureTotalCapacity(allocator, provisional.len);

    var next_id: u32 = 1;
    var prev_module: u32 = std.math.maxInt(u32);
    var prev_kind: types.EntityKind = .namespace;
    var prev_qname: []const u8 = "";
    var prev_id: u32 = 0;

    for (indices) |sorted_idx| {
        const e = provisional[sorted_idx];
        const dup = e.module_id == prev_module and
            e.kind == prev_kind and
            std.mem.eql(u8, e.qualified_name, prev_qname);

        const this_id = if (dup) prev_id else blk: {
            try entities_out.append(allocator, .{
                .id = next_id,
                .kind = e.kind.toString(),
                .qualified_name = e.qualified_name,
                .module_id = e.module_id,
                .def_file_id = e.def_file_id,
                .def_byte_start = e.def_byte_start,
                .def_byte_end = e.def_byte_end,
                .def_line = e.def_line,
                .def_col = e.def_col,
                .is_slab_backed = e.is_slab_backed,
                .is_pub = e.is_pub,
            });
            const id = next_id;
            next_id += 1;
            prev_module = e.module_id;
            prev_kind = e.kind;
            prev_qname = e.qualified_name;
            prev_id = id;
            break :blk id;
        };

        try backfill_out.append(allocator, .{
            .ast_node_id = e.def_ast_node_id,
            .entity_id = this_id,
        });
    }

    return .{
        .final_entities = try entities_out.toOwnedSlice(allocator),
        .ast_backfill = try backfill_out.toOwnedSlice(allocator),
    };
}

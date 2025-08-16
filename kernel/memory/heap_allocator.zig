const std = @import("std");

const intrusive_freelist = @import("intrusive_freelist.zig");
const rbt = @import("red_black_tree.zig");
const slab_alloc = @import("slab_allocator.zig");

const GRANULARITY = 8;
const MAX_ALIGN = ((@as(usize, 1) << @bitSizeOf(u8)) - 1) * GRANULARITY;

pub const AllocHeader = packed struct(u49) {
    is_free: bool,
    bucket_len: u48,
    // 15 unused bits
};

/// Scaled down by granularity (8) to fit in a single byte.
const AllocPadding = packed struct(u8) {
    header_offset: u8,
};

const AllocFooter = packed struct(u48) {
    header: u48,
    // 16 unused bits
};

/// This type is meaningless other than to ensure
/// the intrusive freelist freenode alignment and length
/// is satisfied. The allocation header and footer are not
/// factored into this size. The min len includes the alloc
/// footer size to ensure there's space for it, but the bytes
/// in the freelist entry exclude it so that it's not overwritten
/// when the freelist zeroes out the memory to store it's own metadata.
const FREELIST_ENTRY_LEN = @sizeOf(usize) * 4;
const MIN_LEN = FREELIST_ENTRY_LEN + @sizeOf(AllocFooter);
const MIN_ALIGN = @alignOf(usize);
const FreelistEntry = struct {
    bytes: [FREELIST_ENTRY_LEN]u8 align(MIN_ALIGN),
};

/// Using pop specific enables skipping the tree walk when removing freed
/// tree entries during coalescing in free(). Enabling link to list enables
/// jumping from the freelist entry to the freelist itself to check if popSpecific()
/// removed the last entry, and from there @fieldParentPtr can jump to the tree
/// entry itself to remove it with removeFromPtr() on the tree. The cost of these
/// is an extra 16 bytes required on the minimum allocation length, but the benefit
/// is you don't pay for two O(logn) tree walks if both adjacent blocks can be
/// coalesced, instead it's 3 pointer dereferences per block coalesced.
const using_popSpecific = true;
const link_to_list = true;
const Freelist = intrusive_freelist.IntrusiveFreeList(
    *FreelistEntry,
    using_popSpecific,
    link_to_list,
);

/// The tree is keyed by length, and duplicate length entries are
/// pushed into the freelist.
pub const TreeEntry = struct {
    bucket_len: usize,
    freelist: Freelist,

    pub fn cmpFn(first: TreeEntry, second: TreeEntry) std.math.Order {
        return std.math.order(first.bucket_len, second.bucket_len);
    }
};

const duplicate_is_error = false;
pub const RedBlackTree = rbt.RedBlackTree(
    TreeEntry,
    TreeEntry.cmpFn,
    duplicate_is_error,
);

const stack_bootstrap = false;
const stack_size = 0;
const allocation_chunk_size = 64;
pub const TreeAllocator = slab_alloc.SlabAllocator(
    RedBlackTree.Node,
    stack_bootstrap,
    stack_size,
    allocation_chunk_size,
);

pub const HeapAllocator = struct {
    reserve_start: u48,
    commit_end: u48,
    reserve_end: u48,
    free_tree: RedBlackTree,

    /// Takes a contiguous virtual address space to own.
    /// The tree allocator is made public so it can be initialized
    /// by the caller, allowing them to specify the tree allocator's
    /// backing allocator, and handle the potential error upon
    /// initialization that the slab allocator can return.
    pub fn init(
        reserve_start: u48,
        reserve_end: u48,
        tree_allocator: *TreeAllocator,
    ) HeapAllocator {
        std.debug.assert(std.mem.isAligned(reserve_start, @alignOf(AllocHeader)));
        return .{
            .reserve_start = reserve_start,
            .commit_end = reserve_start,
            .reserve_end = reserve_end,
            .free_tree = RedBlackTree.init(tree_allocator.allocator()),
        };
    }

    pub fn deinit(self: *HeapAllocator) void {
        self.free_tree.deinit();
    }

    pub fn allocator(self: *HeapAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = alloc,
                .resize = resize,
                .remap = remap,
                .free = free,
            },
        };
    }

    fn alloc(
        ptr: *anyopaque,
        len: usize,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ret_addr;
        const self: *HeapAllocator = @alignCast(@ptrCast(ptr));
        const header_align: u48 = @alignOf(AllocHeader);
        std.debug.assert(alignment.toByteUnits() <= MAX_ALIGN);
        std.debug.assert(std.mem.isAligned(self.commit_end, header_align));

        const user_len: u48 = @max(MIN_LEN, @as(u48, @intCast(len)));
        const user_align: u48 = @max(MIN_ALIGN, @as(u48, @intCast(alignment.toByteUnits())));

        var block_base: u48 = 0;
        var user_block_base: u48 = 0;
        var block_end: u48 = 0;

        const key = TreeEntry{ .bucket_len = user_len, .freelist = undefined };
        var node_opt: ?*RedBlackTree.Node = self.free_tree.root;

        outer: while (node_opt) |entry| : (node_opt = entry.getChild(.right)) {
            if (TreeEntry.cmpFn(entry.data, key) == .lt) continue;

            var fnode: ?*Freelist.FreeNode = entry.data.freelist.head;
            while (fnode) |n| : (fnode = n.next) {
                const block_addr: u48 = @intCast(@intFromPtr(n));
                const header_addr: u48 = block_addr - @sizeOf(AllocHeader);
                const header: *AllocHeader = @ptrFromInt(header_addr);
                std.debug.assert(header.is_free);

                const block_size = header.bucket_len;
                const aligned_user = std.mem.alignForward(u48, block_addr, user_align);
                const front_pad = aligned_user - block_addr + 8; // TODO: Make the padding u64
                std.debug.assert(front_pad > 0);

                const body = user_len;
                const tail_pad = std.mem.alignForward(
                    u48,
                    block_addr + front_pad + body,
                    header_align,
                ) - (block_addr + front_pad + body);
                const required = front_pad + body + tail_pad;

                if (required > block_size) continue;

                _ = entry.data.freelist.popSpecific(@ptrFromInt(block_addr)).?;
                if (entry.data.freelist.head == null) {
                    _ = self.free_tree.removeFromPtr(entry);
                }

                const required_bucket_len = required;
                const split_size = block_size - required_bucket_len;
                const block_end_addr = header_addr + @sizeOf(AllocHeader) + block_size;
                const split_needed = @sizeOf(AllocHeader) + @sizeOf(AllocPadding) + MIN_LEN;

                const can_split = split_size >= split_needed;
                if (can_split) {
                    const split_header_addr = header_addr + @sizeOf(AllocHeader) + required_bucket_len;
                    const split_header: *AllocHeader = @ptrFromInt(split_header_addr);
                    split_header.is_free = true;
                    split_header.bucket_len = split_size - @sizeOf(AllocHeader);

                    const split_prefix_end = split_header_addr + @sizeOf(AllocHeader);
                    const split_block_end = split_prefix_end + split_header.bucket_len;
                    const split_footer_addr = split_block_end - @sizeOf(AllocFooter);
                    const split_footer: *AllocFooter = @ptrFromInt(split_footer_addr);
                    split_footer.header = split_header_addr;

                    const split_entry_addr = split_header_addr + @sizeOf(AllocHeader);
                    const split_entry: *FreelistEntry = @ptrFromInt(split_entry_addr);
                    self.treeInsert(split_header.bucket_len, split_entry);

                    block_end = split_header_addr;
                } else {
                    block_end = block_end_addr;
                }

                block_base = header_addr;
                user_block_base = aligned_user;
                break :outer;
            }
        }

        if (block_end == 0) {
            const header_base = self.commit_end;
            const block_addr = header_base + @sizeOf(AllocHeader);
            const aligned_user = std.mem.alignForward(u48, block_addr, user_align);
            const front_pad = aligned_user - block_addr + 8; // TODO: Make the padding u64
            std.debug.assert(front_pad > 0);

            const body = user_len;
            const tail_pad = std.mem.alignForward(
                u48,
                block_addr + front_pad + body,
                header_align,
            ) - (block_addr + front_pad + body);
            const required = front_pad + body + tail_pad;

            const end = header_base + @sizeOf(AllocHeader) + required;
            if (end > self.reserve_end) return null;

            block_base = header_base;
            user_block_base = aligned_user;
            block_end = end;
            self.commit_end = end;
        }

        const header_base = block_base;
        const padding_base = user_block_base - @sizeOf(AllocPadding);
        const bucket_len = block_end - header_base - @sizeOf(AllocHeader);

        const header: *AllocHeader = @ptrFromInt(header_base);
        header.is_free = false;
        header.bucket_len = bucket_len;

        const padding: *AllocPadding = @ptrFromInt(padding_base);
        const scaled = std.math.divExact(u48, user_block_base - header_base, GRANULARITY) catch unreachable;
        std.debug.assert(scaled <= std.math.maxInt(u8));
        padding.header_offset = @intCast(scaled);

        const user_ptr: [*]u8 = @ptrFromInt(user_block_base);
        return user_ptr;
    }

    // no op
    fn resize(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) bool {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    // no op
    fn remap(
        ptr: *anyopaque,
        memory: []u8,
        alignment: std.mem.Alignment,
        new_len: usize,
        ret_addr: usize,
    ) ?[*]u8 {
        _ = ptr;
        _ = memory;
        _ = alignment;
        _ = new_len;
        _ = ret_addr;
        unreachable;
    }

    fn free(
        ptr: *anyopaque,
        buf: []u8,
        alignment: std.mem.Alignment,
        ret_addr: usize,
    ) void {
        _ = alignment;
        _ = ret_addr;
        const self: *HeapAllocator = @alignCast(@ptrCast(ptr));

        const user_addr: u48 = @intCast(@intFromPtr(buf.ptr));
        const padding_addr = user_addr - @sizeOf(AllocPadding);
        const padding_ptr: *AllocPadding = @ptrFromInt(padding_addr);

        const unscaled_header_offset: u48 = @as(u48, padding_ptr.header_offset) * GRANULARITY;
        const header_addr = user_addr - unscaled_header_offset;
        var header_ptr: *AllocHeader = @ptrFromInt(header_addr);
        header_ptr.is_free = true;

        const prefix_end_addr: u48 = @intCast(@intFromPtr(header_ptr) + @sizeOf(AllocHeader));
        const block_end_addr = prefix_end_addr + header_ptr.bucket_len;

        merge_prev: {
            const prev_header_within_bounds = header_addr >= self.reserve_start + @sizeOf(AllocFooter);
            if (!prev_header_within_bounds) break :merge_prev;

            const prev_footer_addr: u48 = header_addr - @sizeOf(AllocFooter);
            const prev_footer: *AllocFooter = @ptrFromInt(prev_footer_addr);
            const prev_header_addr = prev_footer.header;

            const prev_precheck =
                std.mem.isAligned(prev_header_addr, @alignOf(AllocHeader)) and
                prev_header_addr >= self.reserve_start and
                prev_header_addr + @sizeOf(AllocHeader) <= header_addr;
            if (!prev_precheck) break :merge_prev;

            const prev_header: *AllocHeader = @ptrFromInt(prev_header_addr);
            const prev_can_merge =
                prev_header_addr + @sizeOf(AllocHeader) + prev_header.bucket_len == header_addr and
                prev_header.is_free;
            if (!prev_can_merge) break :merge_prev;

            const prev_entry_addr: u48 = prev_header_addr + @sizeOf(AllocHeader);
            const prev_node: *Freelist.FreeNode = @ptrFromInt(prev_entry_addr);
            const prev_list: *Freelist = prev_node.base;

            _ = prev_list.popSpecific(@ptrCast(prev_node)).?;
            if (prev_list.head == null) {
                const prev_entry_ptr: *TreeEntry = @fieldParentPtr("freelist", prev_list);
                const prev_node_ptr: *RedBlackTree.Node = @fieldParentPtr("data", prev_entry_ptr);
                _ = self.free_tree.removeFromPtr(prev_node_ptr);
            }

            header_ptr = prev_header;
            header_ptr.bucket_len = block_end_addr - (prev_header_addr + @sizeOf(AllocHeader));
        }

        merge_next: {
            const current_header_addr: u48 = @intCast(@intFromPtr(header_ptr));
            const next_header_addr: u48 = current_header_addr + @sizeOf(AllocHeader) + header_ptr.bucket_len;
            const next_precheck =
                next_header_addr + @sizeOf(AllocHeader) <= self.commit_end and
                std.mem.isAligned(next_header_addr, @alignOf(AllocHeader));
            if (!next_precheck) break :merge_next;

            const next_header: *AllocHeader = @ptrFromInt(next_header_addr);
            const next_can_merge = next_header.is_free;
            if (!next_can_merge) break :merge_next;

            const next_end: u48 = next_header_addr + @sizeOf(AllocHeader) + next_header.bucket_len;

            const next_entry_addr: u48 = next_header_addr + @sizeOf(AllocHeader);
            const next_node: *Freelist.FreeNode = @ptrFromInt(next_entry_addr);
            const next_list: *Freelist = next_node.base;

            _ = next_list.popSpecific(@ptrCast(next_node)).?;
            if (next_list.head == null) {
                const next_entry_ptr: *TreeEntry = @fieldParentPtr("freelist", next_list);
                const next_node_ptr: *RedBlackTree.Node = @fieldParentPtr("data", next_entry_ptr);
                _ = self.free_tree.removeFromPtr(next_node_ptr);
            }

            const base_addr: u48 = @intCast(@intFromPtr(header_ptr));
            header_ptr.bucket_len = next_end - (base_addr + @sizeOf(AllocHeader));
        }

        const coalesced_prefix_end_addr = @intFromPtr(header_ptr) + @sizeOf(AllocHeader);
        const coalesced_block_end_addr = coalesced_prefix_end_addr + header_ptr.bucket_len;

        const footer_addr = coalesced_block_end_addr - @sizeOf(AllocFooter);
        const footer_ptr: *AllocFooter = @ptrFromInt(footer_addr);
        footer_ptr.header = @intCast(@intFromPtr(header_ptr));

        const freelist_entry_base = @intFromPtr(header_ptr) + @sizeOf(AllocHeader);
        const freelist_entry: *FreelistEntry = @ptrFromInt(freelist_entry_base);

        self.treeInsert(header_ptr.bucket_len, freelist_entry);
    }

    fn treeInsert(
        self: *HeapAllocator,
        bucket_len: u48,
        freelist_entry: *FreelistEntry,
    ) void {
        var current: ?*RedBlackTree.Node = self.free_tree.root;
        var parent: ?*RedBlackTree.Node = null;
        var direction: RedBlackTree.Direction = .left;

        const key: TreeEntry = .{ .bucket_len = bucket_len, .freelist = .{} };

        while (current) |c| {
            parent = c;
            switch (TreeEntry.cmpFn(key, c.data)) {
                .lt => {
                    direction = .left;
                    current = c.getChild(.left);
                },
                .gt => {
                    direction = .right;
                    current = c.getChild(.right);
                },
                .eq => {
                    c.data.freelist.push(freelist_entry);
                    return;
                },
            }
        }

        const new_node = self.free_tree.insertAtPtr(
            parent,
            direction,
            .{ .bucket_len = bucket_len, .freelist = .{} },
        ) catch unreachable;
        new_node.data.freelist.push(freelist_entry);
    }

    /// Helper function for unit tests and fuzzer
    pub fn validateState(self: *HeapAllocator, tmp_alloc: std.mem.Allocator) bool {
        const tree_result = RedBlackTree.validateRedBlackTree(
            self.free_tree.root,
            null,
            null,
        );
        if (!tree_result.valid) return false;
        const BlockInfo = struct {
            header_addr: u48,
            entry_addr: u48, // header + sizeof(AllocHeader)
            end_addr: u48, // header + sizeof(AllocHeader) + bucket_len
            bucket_len: u48,
            is_free: bool,
            found_in_tree: bool,
        };

        const BlockMap = std.HashMap(
            usize,
            BlockInfo,
            std.hash_map.AutoContext(usize),
            std.hash_map.default_max_load_percentage,
        );

        var blocks = BlockMap.init(tmp_alloc);
        defer blocks.deinit();

        const HSIZE: u48 = @sizeOf(AllocHeader);
        const FSIZE: u48 = @sizeOf(AllocFooter);
        const header_align: u48 = @alignOf(AllocHeader);

        const Helper = struct {
            fn fail(
                reason: []const u8,
                ctx: struct {
                    reserve_start: u48 = 0,
                    commit_end: u48 = 0,
                    header_addr: u48 = 0,
                    entry_addr: u48 = 0,
                    end_addr: u48 = 0,
                    bucket_len: u48 = 0,
                    is_free: ?bool = null,
                    extra_a: usize = 0,
                    extra_b: usize = 0,
                },
            ) bool {
                std.debug.print(
                    "\n[Heap Validate Failed]\nreason={s}\nreserve_start={x} commit_end={x}\nheader={x} entry={x} end={x} len={d} is_free={any}\nextra_a={x} extra_b={x}\n",
                    .{
                        reason,
                        ctx.reserve_start,
                        ctx.commit_end,
                        ctx.header_addr,
                        ctx.entry_addr,
                        ctx.end_addr,
                        ctx.bucket_len,
                        ctx.is_free,
                        ctx.extra_a,
                        ctx.extra_b,
                    },
                );
                return false;
            }

            fn hdr(addr: u48) *AllocHeader {
                return @ptrFromInt(addr);
            }
            fn ftr(addr: u48) *AllocFooter {
                return @ptrFromInt(addr);
            }
        };

        // Pass 1: linear memory sweep builds authoritative map
        var cur: u48 = std.mem.alignForward(u48, self.reserve_start, header_align);

        var prev_was_free = false;
        while (cur < self.commit_end) {
            if (cur + HSIZE > self.commit_end)
                return Helper.fail("header beyond commit_end", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                });

            const h = Helper.hdr(cur).*;

            if (h.bucket_len < MIN_LEN)
                return Helper.fail("bucket_len < MIN_LEN", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .bucket_len = h.bucket_len,
                    .is_free = h.is_free,
                });

            const block_end: u48 = cur + HSIZE + h.bucket_len;
            if (block_end > self.commit_end)
                return Helper.fail("block end > commit_end", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .end_addr = block_end,
                    .bucket_len = h.bucket_len,
                    .is_free = h.is_free,
                });

            const footer_addr: u48 = block_end - FSIZE;
            if (h.is_free) {
                const ft = Helper.ftr(footer_addr).*;
                if (ft.header != cur) {
                    std.debug.print("[Heap Validate] extra footer mismatch context: header={x} footer_addr={x} ft.header={x} offset_from_header=+{x}\n", .{
                        cur,
                        footer_addr,
                        ft.header,
                        ft.header - cur,
                    });
                    return Helper.fail("free block footer does not backlink to header", .{
                        .reserve_start = self.reserve_start,
                        .commit_end = self.commit_end,
                        .header_addr = cur,
                        .end_addr = block_end,
                        .bucket_len = h.bucket_len,
                        .is_free = h.is_free,
                        .extra_a = @intCast(ft.header),
                    });
                }
            }

            if (prev_was_free and h.is_free)
                return Helper.fail("adjacent free blocks (coalescing invariant violated)", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .bucket_len = h.bucket_len,
                    .is_free = h.is_free,
                });

            const entry_addr: u48 = cur + HSIZE;
            const info = BlockInfo{
                .header_addr = cur,
                .entry_addr = entry_addr,
                .end_addr = block_end,
                .bucket_len = h.bucket_len,
                .is_free = h.is_free,
                .found_in_tree = false,
            };

            const prev = blocks.fetchPut(@intCast(cur), info) catch {
                return Helper.fail("out of memory inserting into block map", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .bucket_len = h.bucket_len,
                    .is_free = h.is_free,
                });
            };
            if (prev != null)
                return Helper.fail("duplicate header encountered in map", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .bucket_len = h.bucket_len,
                    .is_free = h.is_free,
                });

            prev_was_free = h.is_free;

            const next = std.mem.alignForward(u48, block_end, header_align);
            if (next <= cur)
                return Helper.fail("non-progressing linear walk", .{
                    .reserve_start = self.reserve_start,
                    .commit_end = self.commit_end,
                    .header_addr = cur,
                    .end_addr = block_end,
                    .bucket_len = h.bucket_len,
                    .is_free = h.is_free,
                    .extra_a = next,
                });
            cur = next;
        }

        if (cur != self.commit_end)
            return Helper.fail("walk did not end exactly at commit_end", .{
                .reserve_start = self.reserve_start,
                .commit_end = self.commit_end,
                .extra_a = cur,
            });

        // Pass 2: tree+freelist walk, backlink & metadata checks, mark map
        var stack: [64]?*RedBlackTree.Node = undefined;
        var sp: usize = 0;

        if (self.free_tree.root) |root| {
            stack[sp] = root;
            sp += 1;

            while (sp > 0) {
                sp -= 1;
                const node = stack[sp].?;
                const entry_ptr: *TreeEntry = &node.data;

                var freenode = entry_ptr.freelist.head;
                while (freenode) |fnode| {
                    if (fnode.base != &entry_ptr.freelist)
                        return Helper.fail("freelist entry .base mismatch", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .entry_addr = @intCast(@intFromPtr(fnode)),
                            .extra_a = @intFromPtr(fnode.base),
                            .extra_b = @intFromPtr(&entry_ptr.freelist),
                        });

                    const list_ptr: *Freelist = fnode.base;
                    const parent_entry: *TreeEntry = @fieldParentPtr("freelist", list_ptr);
                    if (parent_entry != entry_ptr)
                        return Helper.fail("freelist back-pointer does not map to current TreeEntry", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .entry_addr = @intCast(@intFromPtr(fnode)),
                            .extra_a = @intFromPtr(parent_entry),
                            .extra_b = @intFromPtr(entry_ptr),
                        });

                    const entry_addr_u48: u48 = @intCast(@intFromPtr(fnode));
                    const header_addr: u48 = entry_addr_u48 - HSIZE;

                    if (header_addr < self.reserve_start or header_addr + HSIZE > self.commit_end)
                        return Helper.fail("freelist-derived header out of bounds", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .entry_addr = entry_addr_u48,
                        });

                    const hptr = Helper.hdr(header_addr);
                    if (!hptr.is_free)
                        return Helper.fail("freelist points to non-free header", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .entry_addr = entry_addr_u48,
                            .bucket_len = hptr.bucket_len,
                            .is_free = hptr.is_free,
                        });

                    if (hptr.bucket_len != entry_ptr.bucket_len)
                        return Helper.fail("tree node bucket_len != header bucket_len", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .entry_addr = entry_addr_u48,
                            .bucket_len = hptr.bucket_len,
                            .extra_a = entry_ptr.bucket_len,
                        });

                    const bend: u48 = header_addr + HSIZE + hptr.bucket_len;
                    if (bend > self.commit_end)
                        return Helper.fail("block end (from freelist) > commit_end", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .end_addr = bend,
                            .bucket_len = hptr.bucket_len,
                            .is_free = hptr.is_free,
                        });

                    const ft = Helper.ftr(bend - FSIZE).*;
                    if (ft.header != header_addr)
                        return Helper.fail("footer backlink mismatch (from freelist)", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .end_addr = bend,
                            .bucket_len = hptr.bucket_len,
                            .extra_a = @intCast(ft.header),
                        });

                    if (blocks.getPtr(@intCast(header_addr))) |bi| {
                        if (!bi.is_free)
                            return Helper.fail("map says allocated but listed in freelist", .{
                                .reserve_start = self.reserve_start,
                                .commit_end = self.commit_end,
                                .header_addr = header_addr,
                                .entry_addr = entry_addr_u48,
                                .bucket_len = bi.bucket_len,
                                .is_free = bi.is_free,
                            });
                        if (bi.entry_addr != entry_addr_u48)
                            return Helper.fail("map entry_addr != freelist entry addr", .{
                                .reserve_start = self.reserve_start,
                                .commit_end = self.commit_end,
                                .header_addr = header_addr,
                                .entry_addr = entry_addr_u48,
                                .extra_a = @intCast(bi.entry_addr),
                            });
                        if (bi.bucket_len != hptr.bucket_len)
                            return Helper.fail("map bucket_len != header bucket_len", .{
                                .reserve_start = self.reserve_start,
                                .commit_end = self.commit_end,
                                .header_addr = header_addr,
                                .bucket_len = hptr.bucket_len,
                                .extra_a = bi.bucket_len,
                            });
                        if (bi.end_addr != bend)
                            return Helper.fail("map end_addr != computed end_addr", .{
                                .reserve_start = self.reserve_start,
                                .commit_end = self.commit_end,
                                .header_addr = header_addr,
                                .end_addr = bend,
                                .extra_a = @intCast(bi.end_addr),
                            });
                        bi.found_in_tree = true;
                    } else {
                        return Helper.fail("free block in tree not found in map", .{
                            .reserve_start = self.reserve_start,
                            .commit_end = self.commit_end,
                            .header_addr = header_addr,
                            .entry_addr = entry_addr_u48,
                            .bucket_len = hptr.bucket_len,
                            .is_free = hptr.is_free,
                        });
                    }

                    freenode = fnode.next;
                }

                if (node.getChild(.left)) |l| {
                    std.debug.assert(sp < stack.len);
                    stack[sp] = l;
                    sp += 1;
                }
                if (node.getChild(.right)) |r| {
                    std.debug.assert(sp < stack.len);
                    stack[sp] = r;
                    sp += 1;
                }
            }
        }

        // Pass 3: post-checks for orphans
        var it = blocks.iterator();
        while (it.next()) |kv| {
            const bi = kv.value_ptr.*;
            if (bi.is_free and !bi.found_in_tree) {
                std.debug.print(
                    "\n[Heap Validate] Orphan free block\nheader={x} entry={x} end={x} len={d}\n",
                    .{ bi.header_addr, bi.entry_addr, bi.end_addr, bi.bucket_len },
                );
                return false;
            }
        }

        return true;
    }
};

test "tree contains after free, then removed after re-alloc (exact fit)" {
    const testing_allocator = std.testing.allocator;
    var tree_allocator = try TreeAllocator.init(testing_allocator);
    defer tree_allocator.deinit();

    const ten_pages = 10 * 4 * 1024;
    const memory = try testing_allocator.alloc(u8, ten_pages);
    defer testing_allocator.free(memory);

    const reserve_start: u48 = @intCast(@intFromPtr(memory.ptr));
    const reserve_end: u48 = reserve_start + @as(u48, @intCast(memory.len));

    var heap_allocator = HeapAllocator.init(reserve_start, reserve_end, &tree_allocator);
    defer heap_allocator.deinit();

    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const alloc = heap_allocator.allocator();

    const N: usize = 128;

    var buf = try alloc.alloc(u8, N);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(buf);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const key_free: TreeEntry = .{ .bucket_len = N + 8, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_free));

    buf = try alloc.alloc(u8, N);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));
    defer {
        alloc.free(buf);
        _ = heap_allocator.validateState(std.testing.allocator);
    }

    try std.testing.expect(!heap_allocator.free_tree.contains(key_free));
}

test "no-split re-alloc consumes the exact-size free block (tail too small to split)" {
    const testing_allocator = std.testing.allocator;
    var tree_allocator = try TreeAllocator.init(testing_allocator);
    defer tree_allocator.deinit();

    const ten_pages = 10 * 4 * 1024;
    const memory = try testing_allocator.alloc(u8, ten_pages);
    defer testing_allocator.free(memory);

    const reserve_start: u48 = @intCast(@intFromPtr(memory.ptr));
    const reserve_end: u48 = reserve_start + @as(u48, @intCast(memory.len));

    var heap_allocator = HeapAllocator.init(reserve_start, reserve_end, &tree_allocator);
    defer heap_allocator.deinit();

    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const alloc = heap_allocator.allocator();

    const L1: usize = 256;
    const big = try alloc.alloc(u8, L1);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(big);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const key_free: TreeEntry = .{ .bucket_len = L1 + 8, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_free));

    const S: usize = 208;
    const small_nosplit = try alloc.alloc(u8, S);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));
    defer {
        alloc.free(small_nosplit);
        _ = heap_allocator.validateState(std.testing.allocator);
    }

    try std.testing.expect(!heap_allocator.free_tree.contains(key_free));
}

test "split path: re-alloc creates a tail block, tree contains tail bucket_len" {
    const testing_allocator = std.testing.allocator;
    var tree_allocator = try TreeAllocator.init(testing_allocator);
    defer tree_allocator.deinit();

    const ten_pages = 10 * 4 * 1024;
    const memory = try testing_allocator.alloc(u8, ten_pages);
    defer testing_allocator.free(memory);

    const reserve_start: u48 = @intCast(@intFromPtr(memory.ptr));
    const reserve_end: u48 = reserve_start + @as(u48, @intCast(memory.len));

    var heap_allocator = HeapAllocator.init(reserve_start, reserve_end, &tree_allocator);
    defer heap_allocator.deinit();

    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const alloc = heap_allocator.allocator();

    const L1: usize = 256;
    const big = try alloc.alloc(u8, L1);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(big);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const key_free: TreeEntry = .{ .bucket_len = L1 + 8, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_free));

    const S: usize = 64;
    const small_split = try alloc.alloc(u8, S);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));
    defer {
        alloc.free(small_split);
        _ = heap_allocator.validateState(std.testing.allocator);
    }

    const tail_bucket_len: usize = 184;

    const key_tail: TreeEntry = .{ .bucket_len = tail_bucket_len, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_tail));
    try std.testing.expect(!heap_allocator.free_tree.contains(key_free));
}

test "triple coalesce: free A, free C, then free B -> one big block" {
    const testing_allocator = std.testing.allocator;
    var tree_allocator = try TreeAllocator.init(testing_allocator);
    defer tree_allocator.deinit();

    const ten_pages = 10 * 4 * 1024;
    const memory = try testing_allocator.alloc(u8, ten_pages);
    defer testing_allocator.free(memory);

    const reserve_start: u48 = @intCast(@intFromPtr(memory.ptr));
    const reserve_end: u48 = reserve_start + @as(u48, @intCast(memory.len));

    var heap_allocator = HeapAllocator.init(reserve_start, reserve_end, &tree_allocator);
    defer heap_allocator.deinit();

    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const alloc = heap_allocator.allocator();

    const A: usize = 128;
    const B: usize = 160;
    const C: usize = 96;

    const a = try alloc.alloc(u8, A);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const b = try alloc.alloc(u8, B);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const c = try alloc.alloc(u8, C);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(a);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(c);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    alloc.free(b);
    try std.testing.expect(heap_allocator.validateState(std.testing.allocator));

    const HSIZE = @sizeOf(AllocHeader);
    const coalesced_len: usize = A + B + C + (5 * HSIZE);

    const key_coalesced: TreeEntry = .{ .bucket_len = coalesced_len, .freelist = undefined };
    try std.testing.expect(heap_allocator.free_tree.contains(key_coalesced));

    const key_A: TreeEntry = .{ .bucket_len = A + 8, .freelist = undefined };
    const key_B: TreeEntry = .{ .bucket_len = B + 8, .freelist = undefined };
    const key_C: TreeEntry = .{ .bucket_len = C + 8, .freelist = undefined };
    try std.testing.expect(!heap_allocator.free_tree.contains(key_A));
    try std.testing.expect(!heap_allocator.free_tree.contains(key_B));
    try std.testing.expect(!heap_allocator.free_tree.contains(key_C));
}

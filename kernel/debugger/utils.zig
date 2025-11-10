//! Debugger utilities and shared helpers for Zag.
//!
//! Types and helpers used by CLI, control, and TUI. Kept separate to avoid
//! cycles and to make unit testing straightforward.
//
//! # Directory
//!
//! ## Type Definitions
//! - `PageEntryFilter` – Filter for page-table walks (indexes, flags, page size).
//
//! ## Constants
//! (none)
//
//! ## Variables
//! (none)
//
//! ## Functions
//! - `matchesFilter` – Test a page entry against a filter.
//! - `parseU64Dec` – Parse unsigned decimal integer.
//! - `threadFromTID` – Return a thread given the TID.

const std = @import("std");
const zag = @import("zag");

const paging = zag.x86.Paging;
const sched = zag.sched.scheduler;

pub const PageEntryFilter = struct {
    l4: ?u9,
    l3: ?u9,
    l2: ?u9,
    l1: ?u9,
    rw: ?paging.RW,
    nx: ?paging.Executeable,
    u: ?paging.User,
    cache: ?paging.Cacheable,
    wrt: ?bool,
    global: ?bool,
    accessed: ?bool,
    dirty: ?bool,
    page4k: ?bool,
    page2m: ?bool,
    page1g: ?bool,
};

pub fn matchesFilter(
    e: paging.PageEntry,
    filter: ?PageEntryFilter,
    l4_idx: ?u64,
    l3_idx: ?u64,
    l2_idx: ?u64,
    l1_idx: ?u64,
    page_size: enum { page4k, page2m, page1g },
) bool {
    const f = filter orelse return true;

    if (f.l4) |idx| {
        if (l4_idx == null or l4_idx.? != idx) return false;
    }
    if (f.l3) |idx| {
        if (l3_idx == null or l3_idx.? != idx) return false;
    }
    if (f.l2) |idx| {
        if (l2_idx == null or l2_idx.? != idx) return false;
    }
    if (f.l1) |idx| {
        if (l1_idx == null or l1_idx.? != idx) return false;
    }

    if (f.rw) |rw| if (e.rw != rw) return false;
    if (f.nx) |nx| if (e.nx != nx) return false;
    if (f.u) |u| if (e.user != u) return false;
    if (f.cache) |cache| if (e.cache_disable != cache) return false;
    if (f.wrt) |wrt| if (e.write_through != wrt) return false;
    if (f.global) |global| if (e.global != global) return false;
    if (f.accessed) |accessed| if (e.accessed != accessed) return false;
    if (f.dirty) |dirty| if (e.dirty != dirty) return false;

    switch (page_size) {
        .page4k => {
            if (f.page4k) |want| if (!want) return false;
            if (f.page2m) |want| if (want) return false;
            if (f.page1g) |want| if (want) return false;
        },
        .page2m => {
            if (f.page2m) |want| if (!want) return false;
            if (f.page4k) |want| if (want) return false;
            if (f.page1g) |want| if (want) return false;
        },
        .page1g => {
            if (f.page1g) |want| if (!want) return false;
            if (f.page4k) |want| if (want) return false;
            if (f.page2m) |want| if (want) return false;
        },
    }

    return true;
}

pub fn parseU64Dec(s: []const u8) ?u64 {
    if (s.len == 0) return null;
    var n: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        const d: u64 = c - '0';
        if (n > (@as(u64, ~@as(u64, 0)) - d) / 10) return null;
        n = n * 10 + d;
    }
    return n;
}

pub fn threadFromTID(tid: u64) ?*sched.Thread {
    var current_thread: ?*sched.Thread = &sched.rq.sentinel;
    while (current_thread) |thread| {
        if (thread.tid == tid) return thread;
        current_thread = thread.next;
    }
    return null;
}

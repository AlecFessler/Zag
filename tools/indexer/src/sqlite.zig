const std = @import("std");

pub const c = @cImport({
    @cInclude("sqlite3.h");
});

pub const Error = error{
    SqliteError,
    Busy,
    Constraint,
    Misuse,
};

pub const Db = struct {
    handle: *c.sqlite3,

    pub fn open(path: [:0]const u8) !Db {
        var handle: ?*c.sqlite3 = null;
        const rc = c.sqlite3_open_v2(
            path.ptr,
            &handle,
            c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE,
            null,
        );
        if (rc != c.SQLITE_OK) {
            if (handle) |h| _ = c.sqlite3_close_v2(h);
            return logErr(handle, rc, "open");
        }
        return .{ .handle = handle.? };
    }

    pub fn close(self: *Db) void {
        _ = c.sqlite3_close_v2(self.handle);
    }

    pub fn exec(self: *Db, sql: [:0]const u8) !void {
        var err_msg: [*c]u8 = null;
        const rc = c.sqlite3_exec(self.handle, sql.ptr, null, null, &err_msg);
        if (rc != c.SQLITE_OK) {
            if (err_msg != null) {
                std.log.err("sqlite exec: {s}", .{err_msg});
                c.sqlite3_free(err_msg);
            }
            return mapErr(rc);
        }
    }

    pub fn prepare(self: *Db, sql: []const u8) !Stmt {
        var stmt: ?*c.sqlite3_stmt = null;
        const rc = c.sqlite3_prepare_v2(
            self.handle,
            sql.ptr,
            @intCast(sql.len),
            &stmt,
            null,
        );
        if (rc != c.SQLITE_OK) return logErr(self.handle, rc, "prepare");
        return .{ .handle = stmt.?, .db = self };
    }

    pub fn lastInsertRowId(self: *Db) i64 {
        return c.sqlite3_last_insert_rowid(self.handle);
    }
};

pub const Stmt = struct {
    handle: *c.sqlite3_stmt,
    db: *Db,

    pub fn finalize(self: *Stmt) void {
        _ = c.sqlite3_finalize(self.handle);
    }

    pub fn reset(self: *Stmt) void {
        _ = c.sqlite3_reset(self.handle);
        _ = c.sqlite3_clear_bindings(self.handle);
    }

    pub fn bindText(self: *Stmt, idx: c_int, value: []const u8) !void {
        const rc = c.sqlite3_bind_text(
            self.handle,
            idx,
            value.ptr,
            @intCast(value.len),
            c.SQLITE_TRANSIENT,
        );
        if (rc != c.SQLITE_OK) return logErr(self.db.handle, rc, "bind_text");
    }

    pub fn bindInt(self: *Stmt, idx: c_int, value: i64) !void {
        const rc = c.sqlite3_bind_int64(self.handle, idx, value);
        if (rc != c.SQLITE_OK) return logErr(self.db.handle, rc, "bind_int");
    }

    pub fn bindBlob(self: *Stmt, idx: c_int, value: []const u8) !void {
        const rc = c.sqlite3_bind_blob(
            self.handle,
            idx,
            value.ptr,
            @intCast(value.len),
            c.SQLITE_TRANSIENT,
        );
        if (rc != c.SQLITE_OK) return logErr(self.db.handle, rc, "bind_blob");
    }

    pub fn bindNull(self: *Stmt, idx: c_int) !void {
        const rc = c.sqlite3_bind_null(self.handle, idx);
        if (rc != c.SQLITE_OK) return logErr(self.db.handle, rc, "bind_null");
    }

    /// Returns true if a row is available; false on SQLITE_DONE.
    pub fn step(self: *Stmt) !bool {
        const rc = c.sqlite3_step(self.handle);
        return switch (rc) {
            c.SQLITE_ROW => true,
            c.SQLITE_DONE => false,
            else => logErr(self.db.handle, rc, "step"),
        };
    }

    /// Convenience: bind nothing, step once, expect DONE.
    pub fn execOnce(self: *Stmt) !void {
        const has_row = try self.step();
        if (has_row) return error.SqliteError;
        self.reset();
    }

    pub fn columnInt(self: *Stmt, idx: c_int) i64 {
        return c.sqlite3_column_int64(self.handle, idx);
    }

    pub fn columnText(self: *Stmt, idx: c_int) []const u8 {
        const ptr = c.sqlite3_column_text(self.handle, idx);
        const len = c.sqlite3_column_bytes(self.handle, idx);
        if (ptr == null or len == 0) return &.{};
        return ptr[0..@intCast(len)];
    }
};

fn mapErr(rc: c_int) Error {
    return switch (rc) {
        c.SQLITE_BUSY => error.Busy,
        c.SQLITE_CONSTRAINT => error.Constraint,
        c.SQLITE_MISUSE => error.Misuse,
        else => error.SqliteError,
    };
}

fn logErr(handle: ?*c.sqlite3, rc: c_int, op: []const u8) Error {
    if (handle) |h| {
        const msg = c.sqlite3_errmsg(h);
        if (msg != null) {
            std.log.err("sqlite {s}: rc={d} {s}", .{ op, rc, msg });
        }
    } else {
        std.log.err("sqlite {s}: rc={d}", .{ op, rc });
    }
    return mapErr(rc);
}

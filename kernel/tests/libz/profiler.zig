const syscall = @import("syscall.zig");
const t = @import("test.zig");

const MAX_UNIQUE_SAMPLES: usize = 256;

pub const ProfileSample = struct {
    rip: u64,
    count: u64,
};

pub const Profiler = struct {
    samples: [MAX_UNIQUE_SAMPLES]ProfileSample,
    num_unique: usize,
    total_samples: u64,

    pub fn init() Profiler {
        return .{
            .samples = [_]ProfileSample{.{ .rip = 0, .count = 0 }} ** MAX_UNIQUE_SAMPLES,
            .num_unique = 0,
            .total_samples = 0,
        };
    }

    pub fn recordSample(self: *Profiler, rip: u64) void {
        self.total_samples += 1;

        // Linear scan for existing entry
        for (self.samples[0..self.num_unique]) |*s| {
            if (s.rip == rip) {
                s.count += 1;
                return;
            }
        }

        // Insert new entry if space available
        if (self.num_unique < MAX_UNIQUE_SAMPLES) {
            self.samples[self.num_unique] = .{ .rip = rip, .count = 1 };
            self.num_unique += 1;
        }
    }

    /// Sort samples by count descending and emit [PROF] lines for top 20.
    pub fn report(self: *Profiler, name: []const u8) void {
        // Sort by count descending (insertion sort)
        var i: usize = 1;
        while (i < self.num_unique) {
            const key = self.samples[i];
            var j: usize = i;
            while (j > 0 and self.samples[j - 1].count < key.count) {
                self.samples[j] = self.samples[j - 1];
                j -= 1;
            }
            self.samples[j] = key;
            i += 1;
        }

        // Header
        syscall.write("[PROF] ");
        syscall.write(name);
        syscall.write(" total_samples=");
        t.printDec(self.total_samples);
        syscall.write("\n");

        // Top 20 entries
        const limit = if (self.num_unique < 20) self.num_unique else 20;
        for (self.samples[0..limit]) |s| {
            syscall.write("[PROF] ");
            syscall.write(name);
            syscall.write(" ");
            t.printHex(s.rip);
            syscall.write(" count=");
            t.printDec(s.count);
            // Percentage: (count * 1000) / total gives tenths of percent
            if (self.total_samples > 0) {
                const pct_x10 = (s.count * 1000) / self.total_samples;
                syscall.write(" pct=");
                t.printDec(pct_x10 / 10);
                syscall.write(".");
                t.printDec(pct_x10 % 10);
            }
            syscall.write("\n");
        }
    }

    /// Returns the RIP with the highest sample count, or null if no samples.
    pub fn topRip(self: *const Profiler) ?u64 {
        if (self.num_unique == 0) return null;
        var best_idx: usize = 0;
        var best_count: u64 = 0;
        for (self.samples[0..self.num_unique], 0..) |s, idx| {
            if (s.count > best_count) {
                best_count = s.count;
                best_idx = idx;
            }
        }
        return self.samples[best_idx].rip;
    }
};

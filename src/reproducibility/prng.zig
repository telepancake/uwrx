//! Hierarchical PRNG system
//!
//! Uses PCG (Permuted Congruential Generator) with hierarchical derivation
//! to provide reproducible random values for each process.

const std = @import("std");

/// PCG state
pub const PcgState = struct {
    state: u64,
    inc: u64,

    pub fn init(seed: u64, stream: u64) PcgState {
        var self = PcgState{
            .state = 0,
            .inc = (stream << 1) | 1,
        };
        _ = self.next();
        self.state +%= seed;
        _ = self.next();
        return self;
    }

    pub fn next(self: *PcgState) u32 {
        const old_state = self.state;
        self.state = old_state *% 6364136223846793005 +% self.inc;

        const xorshifted: u32 = @truncate(((old_state >> 18) ^ old_state) >> 27);
        const rot: u5 = @truncate(old_state >> 59);
        return (xorshifted >> rot) | (xorshifted << ((-%rot) & 31));
    }

    pub fn fillBytes(self: *PcgState, buf: []u8) void {
        var i: usize = 0;
        while (i < buf.len) {
            const val = self.next();
            const bytes = std.mem.asBytes(&val);
            const to_copy = @min(4, buf.len - i);
            @memcpy(buf[i .. i + to_copy], bytes[0..to_copy]);
            i += to_copy;
        }
    }
};

/// Hierarchical PRNG with per-process derivation
pub const HierarchicalPrng = struct {
    root_seed: u64,
    root_state: PcgState,
    /// Per-process states
    process_states: std.AutoHashMap(u32, PcgState),
    allocator: std.mem.Allocator,

    pub fn init(seed: u64) HierarchicalPrng {
        return .{
            .root_seed = seed,
            .root_state = PcgState.init(seed, 0),
            .process_states = std.AutoHashMap(u32, PcgState).init(std.heap.page_allocator),
            .allocator = std.heap.page_allocator,
        };
    }

    pub fn deinit(self: *HierarchicalPrng) void {
        self.process_states.deinit();
    }

    /// Get or create PRNG state for a process
    pub fn getState(self: *HierarchicalPrng, pid: u32) *PcgState {
        const gop = self.process_states.getOrPut(pid) catch {
            return &self.root_state;
        };

        if (!gop.found_existing) {
            // Derive new state from root seed and pid
            const derived_seed = self.root_seed ^ (@as(u64, pid) *% 0x9e3779b97f4a7c15);
            gop.value_ptr.* = PcgState.init(derived_seed, pid);
        }

        return gop.value_ptr;
    }

    /// Fill buffer with random bytes for a process
    pub fn fillBytes(self: *HierarchicalPrng, pid: u32, buf: []u8) void {
        const state = self.getState(pid);
        state.fillBytes(buf);
    }

    /// Get AT_RANDOM bytes for a process
    pub fn getAtRandom(self: *HierarchicalPrng, pid: u32) [16]u8 {
        var buf: [16]u8 = undefined;
        self.fillBytes(pid, &buf);
        return buf;
    }

    /// Get a u64 for a process
    pub fn getU64(self: *HierarchicalPrng, pid: u32) u64 {
        const state = self.getState(pid);
        const low = state.next();
        const high = state.next();
        return (@as(u64, high) << 32) | @as(u64, low);
    }
};

/// Simple derivation for thread-local PRNG
pub fn deriveThreadSeed(process_seed: u64, thread_id: u32) u64 {
    return process_seed ^ (@as(u64, thread_id) *% 0xbf58476d1ce4e5b9);
}

test "PcgState determinism" {
    var prng1 = PcgState.init(12345, 1);
    var prng2 = PcgState.init(12345, 1);

    // Same seed should produce same sequence
    try std.testing.expectEqual(prng1.next(), prng2.next());
    try std.testing.expectEqual(prng1.next(), prng2.next());
    try std.testing.expectEqual(prng1.next(), prng2.next());
}

test "HierarchicalPrng per-process isolation" {
    var hier_prng = HierarchicalPrng.init(12345);
    defer hier_prng.deinit();

    const val1 = hier_prng.getU64(2);
    const val2 = hier_prng.getU64(3);

    // Different processes should get different values (with high probability)
    try std.testing.expect(val1 != val2);

    // Same process should be consistent
    var hier_prng2 = HierarchicalPrng.init(12345);
    defer hier_prng2.deinit();

    const val1_again = hier_prng2.getU64(2);
    try std.testing.expectEqual(val1, val1_again);
}

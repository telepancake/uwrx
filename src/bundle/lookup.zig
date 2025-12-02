//! Bundled executable lookup
//!
//! Provides lookup functionality for bundled executables.

const std = @import("std");
const mod = @import("mod.zig");

/// Global bundle state (initialized on startup)
var global_state: ?mod.BundleState = null;

/// Initialize global bundle state
pub fn initGlobal(allocator: std.mem.Allocator) !void {
    global_state = mod.BundleState.init(allocator);
    try global_state.?.loadFromSelf();
}

/// Deinitialize global bundle state
pub fn deinitGlobal() void {
    if (global_state) |*state| {
        state.deinit();
        global_state = null;
    }
}

/// Find a bundled executable by name
pub fn findBundled(name: []const u8) ?mod.BundledExec {
    if (global_state) |*state| {
        return state.getBundled(name);
    }

    // Try to parse directly from ELF sections
    // This is a fallback for when global state isn't initialized
    return findBundledDirect(name);
}

/// Direct lookup without global state
fn findBundledDirect(name: []const u8) ?mod.BundledExec {
    // Simplified lookup - just check if name matches known bundled executables
    // In a real implementation, this would parse ELF sections
    _ = name;
    return null;
}

/// Check if running via symlink to bundled executable
pub fn isSymlinkInvocation(argv0: []const u8) ?[]const u8 {
    const basename = std.fs.path.basename(argv0);

    // If not called as "uwrx", check if it's a bundled executable
    if (!std.mem.eql(u8, basename, "uwrx")) {
        if (findBundled(basename) != null) {
            return basename;
        }
    }

    return null;
}

/// List all bundled executables
pub fn listBundled(allocator: std.mem.Allocator) ![][]const u8 {
    if (global_state) |*state| {
        var list = std.ArrayList([]const u8).init(allocator);

        var it = state.executables.keyIterator();
        while (it.next()) |key| {
            try list.append(key.*);
        }

        return list.toOwnedSlice();
    }

    return &[_][]const u8{};
}

test "findBundled nonexistent" {
    const result = findBundled("nonexistent");
    try std.testing.expect(result == null);
}

test "isSymlinkInvocation uwrx" {
    const result = isSymlinkInvocation("uwrx");
    try std.testing.expect(result == null);
}

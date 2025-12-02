//! Process whitelist for partial rebuild
//!
//! Defines which processes can be skipped during partial rebuild.

const std = @import("std");

/// Default whitelisted executables
pub const DEFAULT_WHITELIST = [_][]const u8{
    // C compilers
    "cc",
    "gcc",
    "g++",
    "clang",
    "clang++",
    "cc1",
    "cc1plus",

    // Linker
    "ld",
    "ld.bfd",
    "ld.gold",
    "ld.lld",
    "lld",
    "collect2",

    // Assembler
    "as",
    "gas",

    // Archiver
    "ar",
    "ranlib",

    // Object tools
    "nm",
    "objcopy",
    "objdump",
    "strip",
    "size",
    "strings",

    // Other common tools
    "cpp",
    "m4",
    "flex",
    "bison",
    "yacc",
};

/// Whitelist state
pub const Whitelist = struct {
    allocator: std.mem.Allocator,
    entries: std.StringHashMap(void),

    pub fn init(allocator: std.mem.Allocator) Whitelist {
        var self = Whitelist{
            .allocator = allocator,
            .entries = std.StringHashMap(void).init(allocator),
        };

        // Add default entries
        for (DEFAULT_WHITELIST) |entry| {
            self.entries.put(entry, {}) catch {};
        }

        return self;
    }

    pub fn deinit(self: *Whitelist) void {
        self.entries.deinit();
    }

    /// Check if an executable is whitelisted
    pub fn isWhitelisted(self: *Whitelist, name: []const u8) bool {
        // Get basename
        const basename = std.fs.path.basename(name);
        return self.entries.contains(basename);
    }

    /// Add an executable to the whitelist
    pub fn add(self: *Whitelist, name: []const u8) !void {
        const name_copy = try self.allocator.dupe(u8, name);
        try self.entries.put(name_copy, {});
    }

    /// Remove an executable from the whitelist
    pub fn remove(self: *Whitelist, name: []const u8) void {
        _ = self.entries.remove(name);
    }
};

test "Whitelist defaults" {
    const allocator = std.testing.allocator;

    var wl = Whitelist.init(allocator);
    defer wl.deinit();

    try std.testing.expect(wl.isWhitelisted("gcc"));
    try std.testing.expect(wl.isWhitelisted("/usr/bin/gcc"));
    try std.testing.expect(wl.isWhitelisted("clang"));
    try std.testing.expect(!wl.isWhitelisted("python"));
}

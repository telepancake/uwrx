//! Sources module
//!
//! Manages read-only source mappings for the filesystem.
//! Sources provide input files as the base layer.

const std = @import("std");

pub const types = @import("types.zig");
pub const host = @import("host.zig");
pub const tar = @import("tar.zig");
pub const git = @import("git.zig");
pub const oci = @import("oci.zig");
pub const squashfs = @import("squashfs.zig");

pub const SourceType = types.SourceType;
pub const Source = types.Source;
pub const SourceSpec = types.SourceSpec;

/// Parse a source specification string
pub fn parseSpec(spec: []const u8) !SourceSpec {
    return types.parseSourceSpec(spec);
}

/// Create a source from a specification
pub fn createSource(allocator: std.mem.Allocator, spec: SourceSpec) !Source {
    return types.createSource(allocator, spec);
}

test {
    _ = types;
    _ = host;
    _ = tar;
    _ = git;
    _ = oci;
    _ = squashfs;
}

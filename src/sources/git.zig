//! Git repository source (future implementation)

const std = @import("std");
const types = @import("types.zig");

/// Git source (placeholder)
pub const GitSource = struct {
    // TODO: Implement git source
    // This would:
    // 1. Access git repository at given path
    // 2. Checkout specified treeish (default HEAD)
    // 3. Provide read-only access to files
    // 4. Support optional subpath extraction
};

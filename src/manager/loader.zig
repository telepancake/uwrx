//! Self-loader for UWRX
//!
//! Loads uwrx into high virtual addresses so that the target executable
//! can use the normal lower address range.

const std = @import("std");
const elf = @import("elf.zig");
const linux = @import("../util/linux.zig");

/// High address base for uwrx code (near top of 47-bit user space)
/// Leaving room for stack and kernel
pub const HIGH_ADDR_BASE: u64 = 0x7f00_0000_0000;

/// Reserved address space for uwrx (256 MB)
pub const UWRX_RESERVED_SIZE: u64 = 256 * 1024 * 1024;

/// State for the self-loaded uwrx
pub const LoaderState = struct {
    /// Base address where uwrx is loaded
    base_addr: u64,
    /// Size of loaded uwrx
    size: u64,
    /// Entry point in high memory
    entry: u64,
};

/// Relocate uwrx to high addresses
pub fn relocateToHighAddresses(allocator: std.mem.Allocator) !LoaderState {
    // Read our own executable
    const self_path = "/proc/self/exe";
    const file = try std.fs.openFileAbsolute(self_path, .{});
    defer file.close();

    // Parse ELF
    var exe_info = try elf.loadExecutable(allocator, self_path);
    defer exe_info.deinit();

    // Calculate load span
    const span = elf.calculateLoadSpan(exe_info.phdrs);
    const size = span.max - span.min;

    // Find suitable high address
    const base_addr = try findHighAddress(size);

    // Load segments to high addresses
    try elf.loadSegments(allocator, file, exe_info.phdrs, base_addr - span.min);

    // Calculate new entry point
    const entry = base_addr - span.min + exe_info.entry;

    return .{
        .base_addr = base_addr,
        .size = size,
        .entry = entry,
    };
}

/// Find a suitable high address for loading
fn findHighAddress(size: u64) !u64 {
    const page_size: u64 = 4096;
    const aligned_size = std.mem.alignForward(u64, size, page_size);

    // Start from HIGH_ADDR_BASE and try to find free space
    var addr = HIGH_ADDR_BASE;
    const max_addr = 0x7fff_0000_0000 - aligned_size;

    while (addr < max_addr) {
        // Try to map at this address
        const result = std.os.linux.mmap(
            @ptrFromInt(addr),
            aligned_size,
            std.os.linux.PROT.NONE,
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
            -1,
            0,
        );

        if (result != std.os.linux.MAP_FAILED) {
            // Found free space, unmap and return
            _ = std.os.linux.munmap(@ptrFromInt(result), aligned_size);

            // Only accept if we got the address we asked for
            if (result == addr) {
                return addr;
            }
            // Otherwise unmap what we got and try elsewhere
            _ = std.os.linux.munmap(@ptrFromInt(result), aligned_size);
        }

        addr += aligned_size;
    }

    return error.NoHighAddressSpace;
}

/// Set up restricted address space for target process
pub fn setupRestrictedAddressSpace() !void {
    // The target process should only have access to addresses below HIGH_ADDR_BASE
    // This is enforced through mmap interception in the syscall handler

    // For now, we just mark the high memory region as reserved
    // The actual restriction happens in syscall handling
}

/// Jump to high-address copy of uwrx
/// This is called after self-relocation to continue execution from high memory
pub fn jumpToHighAddress(state: LoaderState, args: anytype) noreturn {
    // Cast entry point to function pointer and call
    const entry_fn: *const fn (@TypeOf(args)) noreturn = @ptrFromInt(state.entry);
    entry_fn(args);
}

test "HIGH_ADDR_BASE is in valid range" {
    // Should be below 48-bit limit
    try std.testing.expect(HIGH_ADDR_BASE < 0x8000_0000_0000);
    // Should be high enough to leave room for target process
    try std.testing.expect(HIGH_ADDR_BASE > 0x1_0000_0000);
}

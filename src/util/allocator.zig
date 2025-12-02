//! Custom allocators for uwrx
//! Provides specialized memory allocation strategies

const std = @import("std");
const linux = @import("linux.zig");

/// Arena allocator backed by anonymous memory (memfd)
/// Useful for allocations that don't need to be freed individually
pub const MmapArena = struct {
    base: [*]u8,
    size: usize,
    offset: usize,
    fd: std.os.linux.fd_t,

    const page_size = 4096;

    pub fn init(size: usize) !MmapArena {
        const aligned_size = std.mem.alignForward(usize, size, page_size);

        // Create anonymous file
        const fd = try linux.memfdCreate("uwrx_arena", linux.MFD_CLOEXEC);
        errdefer std.os.linux.close(fd);

        // Set size
        const truncate_result = std.os.linux.ftruncate(fd, @intCast(aligned_size));
        if (truncate_result != 0) {
            return error.TruncateFailed;
        }

        // Map memory
        const mmap_result = std.os.linux.mmap(
            null,
            aligned_size,
            std.os.linux.PROT.READ | std.os.linux.PROT.WRITE,
            .{ .TYPE = .SHARED },
            fd,
            0,
        );

        if (mmap_result == std.os.linux.MAP_FAILED) {
            return error.MmapFailed;
        }

        return .{
            .base = @ptrFromInt(mmap_result),
            .size = aligned_size,
            .offset = 0,
            .fd = fd,
        };
    }

    pub fn deinit(self: *MmapArena) void {
        _ = std.os.linux.munmap(self.base, self.size);
        std.os.linux.close(self.fd);
    }

    pub fn alloc(self: *MmapArena, len: usize, alignment: u8) ?[*]u8 {
        const aligned_offset = std.mem.alignForward(usize, self.offset, @as(usize, 1) << @intCast(alignment));
        if (aligned_offset + len > self.size) {
            return null;
        }
        const result = self.base + aligned_offset;
        self.offset = aligned_offset + len;
        return result;
    }

    pub fn reset(self: *MmapArena) void {
        self.offset = 0;
    }

    /// Get a std.mem.Allocator interface
    pub fn allocator(self: *MmapArena) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocFn,
                .resize = resizeFn,
                .free = freeFn,
            },
        };
    }

    fn allocFn(ctx: *anyopaque, len: usize, ptr_align: u8, _: usize) ?[*]u8 {
        const self: *MmapArena = @ptrCast(@alignCast(ctx));
        return self.alloc(len, ptr_align);
    }

    fn resizeFn(_: *anyopaque, _: []u8, _: u8, _: usize, _: usize) bool {
        // Arena doesn't support resize
        return false;
    }

    fn freeFn(_: *anyopaque, _: []u8, _: u8, _: usize) void {
        // Arena doesn't free individual allocations
    }
};

/// Fixed buffer allocator for stack-based temporary allocations
pub const StackBuffer = struct {
    buffer: []u8,
    offset: usize,

    pub fn init(buffer: []u8) StackBuffer {
        return .{
            .buffer = buffer,
            .offset = 0,
        };
    }

    pub fn alloc(self: *StackBuffer, len: usize, alignment: u8) ?[]u8 {
        const aligned_offset = std.mem.alignForward(usize, self.offset, @as(usize, 1) << @intCast(alignment));
        if (aligned_offset + len > self.buffer.len) {
            return null;
        }
        const result = self.buffer[aligned_offset .. aligned_offset + len];
        self.offset = aligned_offset + len;
        return result;
    }

    pub fn reset(self: *StackBuffer) void {
        self.offset = 0;
    }

    pub fn allocator(self: *StackBuffer) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &.{
                .alloc = allocFn,
                .resize = resizeFn,
                .free = freeFn,
            },
        };
    }

    fn allocFn(ctx: *anyopaque, len: usize, ptr_align: u8, _: usize) ?[*]u8 {
        const self: *StackBuffer = @ptrCast(@alignCast(ctx));
        const result = self.alloc(len, ptr_align) orelse return null;
        return result.ptr;
    }

    fn resizeFn(_: *anyopaque, _: []u8, _: u8, _: usize, _: usize) bool {
        return false;
    }

    fn freeFn(_: *anyopaque, _: []u8, _: u8, _: usize) void {
        // Stack buffer doesn't free individual allocations
    }
};

/// Page-aligned allocator for memory that will be used with mmap/mprotect
pub fn allocPages(num_pages: usize) ![]align(4096) u8 {
    const size = num_pages * 4096;
    const result = std.os.linux.mmap(
        null,
        size,
        std.os.linux.PROT.READ | std.os.linux.PROT.WRITE,
        .{ .TYPE = .PRIVATE, .ANONYMOUS = true },
        -1,
        0,
    );

    if (result == std.os.linux.MAP_FAILED) {
        return error.MmapFailed;
    }

    const ptr: [*]align(4096) u8 = @ptrFromInt(result);
    return ptr[0..size];
}

pub fn freePages(pages: []align(4096) u8) void {
    _ = std.os.linux.munmap(@alignCast(pages.ptr), pages.len);
}

test "StackBuffer allocation" {
    var buffer: [1024]u8 = undefined;
    var stack = StackBuffer.init(&buffer);

    const a1 = stack.alloc(100, 0);
    try std.testing.expect(a1 != null);

    const a2 = stack.alloc(100, 3); // 8-byte aligned
    try std.testing.expect(a2 != null);

    // Should fail - not enough space
    const a3 = stack.alloc(1000, 0);
    try std.testing.expect(a3 == null);

    stack.reset();

    // Should succeed after reset
    const a4 = stack.alloc(1000, 0);
    try std.testing.expect(a4 != null);
}

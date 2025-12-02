//! Syscall handler for intercepted syscalls
//!
//! Processes seccomp notifications and handles syscalls appropriately
//! based on uwrx's requirements (filesystem overlay, network isolation, etc.)
//!
//! IMPORTANT: Manager thread and target thread share the same address space
//! (via CLONE_VM). This means we can directly access pointers from syscall
//! arguments without needing process_vm_writev.

const std = @import("std");
const linux = @import("../util/linux.zig");
const seccomp = @import("seccomp.zig");
const prng = @import("../reproducibility/prng.zig");
const time_mod = @import("../reproducibility/time.zig");
const filesystem = @import("../filesystem/mod.zig");
const network = @import("../network/mod.zig");
const timestamp_mod = @import("../filesystem/timestamp.zig");
const whiteout = @import("../filesystem/whiteout.zig");
const remap = @import("../filesystem/remap.zig");

/// Syscall handler context
pub const HandlerContext = struct {
    allocator: std.mem.Allocator,
    seccomp_fd: linux.fd_t,
    /// Hierarchical PRNG for reproducible random
    prng_state: ?*prng.HierarchicalPrng = null,
    /// Deterministic time state
    time_state: ?*time_mod.DeterministicTime = null,
    /// Filesystem state
    fs_state: ?*filesystem.FilesystemState = null,
    /// Network state
    net_state: ?*network.NetworkState = null,
    /// Timestamp state for stat squashing
    timestamp_state: ?*timestamp_mod.TimestampState = null,
    /// Path remapper for special paths
    path_remapper: ?*remap.PathRemapper = null,
    /// Current working directory (tracked per process would need more state)
    cwd: []const u8 = "/",
    /// Files directory for writes
    files_dir: []const u8 = "/tmp/uwrx/files",
};

/// Handle syscall notifications in a loop
pub fn handleLoop(ctx: *HandlerContext) !void {
    while (true) {
        const notif = seccomp.recvNotification(ctx.seccomp_fd) catch |err| switch (err) {
            error.RecvFailed => continue,
            else => return err,
        };

        const resp = handleSyscall(ctx, &notif);

        seccomp.sendResponse(ctx.seccomp_fd, &resp) catch |err| switch (err) {
            error.SendFailed => continue,
            else => return err,
        };
    }
}

/// Handle a single syscall notification
fn handleSyscall(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Check if notification is still valid (TOCTOU protection)
    if (!seccomp.isIdValid(ctx.seccomp_fd, notif.id)) {
        return seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.NOSYS));
    }

    return switch (notif.data.nr) {
        // Process syscalls
        linux.SYS.clone, linux.SYS.clone3, linux.SYS.fork, linux.SYS.vfork => handleProcessCreate(ctx, notif),
        linux.SYS.execve, linux.SYS.execveat => handleExec(ctx, notif),
        linux.SYS.exit, linux.SYS.exit_group => handleExit(ctx, notif),

        // File syscalls
        linux.SYS.open, linux.SYS.openat, linux.SYS.openat2, linux.SYS.creat => handleOpen(ctx, notif),
        linux.SYS.stat, linux.SYS.lstat, linux.SYS.fstat, linux.SYS.newfstatat, linux.SYS.statx => handleStat(ctx, notif),
        linux.SYS.access, linux.SYS.faccessat => handleAccess(ctx, notif),
        linux.SYS.unlink, linux.SYS.unlinkat, linux.SYS.rmdir => handleUnlink(ctx, notif),
        linux.SYS.rename, linux.SYS.renameat, linux.SYS.renameat2 => handleRename(ctx, notif),
        linux.SYS.mkdir, linux.SYS.mkdirat => handleMkdir(ctx, notif),
        linux.SYS.readlink, linux.SYS.readlinkat => handleReadlink(ctx, notif),
        linux.SYS.getdents64 => handleGetdents(ctx, notif),
        linux.SYS.getcwd => handleGetcwd(ctx, notif),
        linux.SYS.chdir, linux.SYS.fchdir => handleChdir(ctx, notif),
        linux.SYS.chmod, linux.SYS.fchmod, linux.SYS.fchmodat => handleChmod(ctx, notif),
        linux.SYS.chown, linux.SYS.fchown, linux.SYS.lchown, linux.SYS.fchownat => handleChown(ctx, notif),
        linux.SYS.utimensat => handleUtimensat(ctx, notif),

        // Network syscalls
        linux.SYS.socket => handleSocket(ctx, notif),
        linux.SYS.connect => handleConnect(ctx, notif),
        linux.SYS.bind => handleBind(ctx, notif),
        linux.SYS.listen => handleListen(ctx, notif),
        linux.SYS.accept, linux.SYS.accept4 => handleAccept(ctx, notif),
        linux.SYS.sendto, linux.SYS.sendmsg => handleSend(ctx, notif),
        linux.SYS.recvfrom, linux.SYS.recvmsg => handleRecv(ctx, notif),
        linux.SYS.getsockopt, linux.SYS.setsockopt => handleSockopt(ctx, notif),
        linux.SYS.getpeername, linux.SYS.getsockname => handleSockname(ctx, notif),

        // Random syscalls
        linux.SYS.getrandom => handleGetrandom(ctx, notif),

        // Time syscalls
        linux.SYS.clock_gettime => handleClockGettime(ctx, notif),
        linux.SYS.gettimeofday => handleGettimeofday(ctx, notif),
        linux.SYS.time => handleTimeSyscall(ctx, notif),

        else => seccomp.continueResponse(notif.id),
    };
}

// ============================================================================
// Process syscall handlers
// ============================================================================

fn handleProcessCreate(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // For process creation, we need to set up the new process with manager thread
    // For now, just continue and let it proceed
    return seccomp.continueResponse(notif.id);
}

fn handleExec(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // On exec, check if it's a bundled executable
    // For now, just continue
    return seccomp.continueResponse(notif.id);
}

fn handleExit(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Clean up any resources for this process
    return seccomp.continueResponse(notif.id);
}

// ============================================================================
// File syscall handlers
// ============================================================================

/// Handle open/openat/openat2/creat syscalls
/// Redirect file access through overlay filesystem
///
/// open(pathname, flags, mode) -> fd
/// openat(dirfd, pathname, flags, mode) -> fd
/// openat2(dirfd, pathname, how, size) -> fd
/// creat(pathname, mode) -> fd
fn handleOpen(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const syscall_nr = notif.data.nr;

    // Get path pointer based on syscall type
    const path_ptr: u64 = switch (syscall_nr) {
        linux.SYS.open, linux.SYS.creat => notif.data.args[0],
        linux.SYS.openat, linux.SYS.openat2 => notif.data.args[1],
        else => return seccomp.continueResponse(notif.id),
    };

    // Get flags and mode
    const flags: u32 = blk: {
        const raw_flags: u64 = switch (syscall_nr) {
            linux.SYS.open => notif.data.args[1],
            linux.SYS.creat => 0o100 | 0o1 | 0o1000, // O_CREAT | O_WRONLY | O_TRUNC
            linux.SYS.openat => notif.data.args[2],
            linux.SYS.openat2 => openat2_blk: {
                const how_ptr = notif.data.args[2];
                if (how_ptr == 0) {
                    return seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.FAULT));
                }
                const flags_ptr: *const u64 = @ptrFromInt(how_ptr);
                break :openat2_blk flags_ptr.*;
            },
            else => 0,
        };
        break :blk @truncate(raw_flags);
    };

    const mode: u32 = blk: {
        const raw_mode: u64 = switch (syscall_nr) {
            linux.SYS.open => notif.data.args[2],
            linux.SYS.creat => notif.data.args[1],
            linux.SYS.openat => notif.data.args[3],
            linux.SYS.openat2 => openat2_blk: {
                const how_ptr = notif.data.args[2];
                if (how_ptr == 0) break :openat2_blk 0;
                // mode is second field in open_how
                const mode_ptr: *const u64 = @ptrFromInt(how_ptr + 8);
                break :openat2_blk mode_ptr.*;
            },
            else => 0,
        };
        break :blk @truncate(raw_mode);
    };

    if (path_ptr == 0) {
        return seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.FAULT));
    }

    // Read path string (same address space - direct access)
    const path_cstr: [*:0]const u8 = @ptrFromInt(path_ptr);
    const path = std.mem.span(path_cstr);

    // Handle special paths first
    if (ctx.path_remapper) |remapper| {
        // Handle /dev/urandom and /dev/random - let them through
        if (remap.PathRemapper.isRandomDevice(path)) {
            return seccomp.continueResponse(notif.id);
        }

        // Check for remapped paths (CA certs, resolv.conf, etc.)
        if (remapper.remap(path)) |remapped_path| {
            // Execute open with remapped path
            const result = executeOpen(remapped_path, flags, mode);
            if (result < 0) {
                return seccomp.errorResponse(notif.id, @intCast(-result));
            }
            return seccomp.successResponse(notif.id, result);
        }
    }

    // O_WRONLY=1, O_RDWR=2, O_CREAT=0o100, O_TRUNC=0o1000
    const is_write = (flags & (0o1 | 0o2 | 0o100 | 0o1000)) != 0;

    // Check filesystem overlay
    if (ctx.fs_state) |fs_state| {
        if (is_write) {
            // Get write path through overlay (copy-on-write)
            const write_path = fs_state.openForWrite(path, notif.pid) catch {
                return seccomp.continueResponse(notif.id);
            };
            defer ctx.allocator.free(write_path);

            // Ensure parent directory exists
            ensureParentDir(write_path);

            // Record the modification
            fs_state.recordWrite(path, notif.pid) catch {};

            // Execute open with the overlay write path
            const result = executeOpen(write_path, flags, mode);
            if (result < 0) {
                return seccomp.errorResponse(notif.id, @intCast(-result));
            }
            return seccomp.successResponse(notif.id, result);
        } else {
            // Read-only: resolve through overlay to find actual file location
            if (fs_state.resolvePath(path, notif.pid) catch null) |layer_path| {
                // Build full path: layer_path + original path
                var full_path_buf: [4096]u8 = undefined;
                const full_path = std.fmt.bufPrintZ(&full_path_buf, "{s}{s}", .{ layer_path, path }) catch {
                    return seccomp.continueResponse(notif.id);
                };

                const result = executeOpen(full_path, flags, mode);
                if (result < 0) {
                    return seccomp.errorResponse(notif.id, @intCast(-result));
                }
                return seccomp.successResponse(notif.id, result);
            }
        }
    }

    // No overlay configured - let syscall proceed with original path
    return seccomp.continueResponse(notif.id);
}

/// Execute an open syscall with the given path
fn executeOpen(path: []const u8, flags: u32, mode: u32) i64 {
    // Need null-terminated path
    var path_buf: [4096]u8 = undefined;
    if (path.len >= path_buf.len) {
        return -@as(i64, @intFromEnum(std.os.linux.E.NAMETOOLONG));
    }
    @memcpy(path_buf[0..path.len], path);
    path_buf[path.len] = 0;

    const result = std.os.linux.syscall4(
        .openat,
        @as(usize, @bitCast(@as(isize, std.os.linux.AT.FDCWD))),
        @intFromPtr(&path_buf),
        flags,
        mode,
    );

    return @bitCast(result);
}

/// Ensure parent directory exists for a path
fn ensureParentDir(path: []const u8) void {
    if (std.fs.path.dirname(path)) |parent| {
        // Recursively create parent directories
        std.fs.makeDirAbsolute(parent) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            error.FileNotFound => {
                // Parent of parent doesn't exist, recurse
                ensureParentDir(parent);
                std.fs.makeDirAbsolute(parent) catch {};
            },
            else => {},
        };
    }
}

/// Handle stat/lstat/fstat/newfstatat/statx syscalls
/// Squash timestamps and normalize uid/gid for reproducibility
///
/// stat(pathname, statbuf) -> int
/// lstat(pathname, statbuf) -> int
/// fstat(fd, statbuf) -> int
/// newfstatat(dirfd, pathname, statbuf, flags) -> int
/// statx(dirfd, pathname, flags, mask, statxbuf) -> int
fn handleStat(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const timestamp_state = ctx.timestamp_state orelse {
        return seccomp.continueResponse(notif.id);
    };

    const syscall_nr = notif.data.nr;

    // Let the syscall execute first
    // We need to post-process the result to squash timestamps
    // Since seccomp USER_NOTIF doesn't support post-processing,
    // we need to execute the syscall ourselves and return the result

    // Get stat buffer pointer based on syscall type
    const stat_ptr: u64 = switch (syscall_nr) {
        linux.SYS.stat, linux.SYS.lstat => notif.data.args[1],
        linux.SYS.fstat => notif.data.args[1],
        linux.SYS.newfstatat => notif.data.args[2],
        linux.SYS.statx => notif.data.args[4],
        else => return seccomp.continueResponse(notif.id),
    };

    if (stat_ptr == 0) {
        return seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.FAULT));
    }

    // Let the syscall proceed, then modify the result
    // For proper implementation, we would:
    // 1. Execute the syscall ourselves
    // 2. Modify the timestamps in the result
    // 3. Return the modified result
    //
    // Since we share address space, after syscall completes we can
    // modify the stat buffer directly. However, seccomp USER_NOTIF
    // doesn't have a "post-execute" hook.
    //
    // Workaround: Execute syscall ourselves using raw syscall
    const result: isize = switch (syscall_nr) {
        linux.SYS.stat => blk: {
            const path_ptr = notif.data.args[0];
            if (path_ptr == 0) break :blk -@as(isize, @intFromEnum(std.os.linux.E.FAULT));
            const stat_buf: *std.os.linux.Stat = @ptrFromInt(stat_ptr);
            const path_cstr: [*:0]const u8 = @ptrFromInt(path_ptr);
            break :blk @bitCast(std.os.linux.syscall2(
                .stat,
                @intFromPtr(path_cstr),
                @intFromPtr(stat_buf),
            ));
        },
        linux.SYS.lstat => blk: {
            const path_ptr = notif.data.args[0];
            if (path_ptr == 0) break :blk -@as(isize, @intFromEnum(std.os.linux.E.FAULT));
            const stat_buf: *std.os.linux.Stat = @ptrFromInt(stat_ptr);
            const path_cstr: [*:0]const u8 = @ptrFromInt(path_ptr);
            break :blk @bitCast(std.os.linux.syscall2(
                .lstat,
                @intFromPtr(path_cstr),
                @intFromPtr(stat_buf),
            ));
        },
        linux.SYS.fstat => blk: {
            const fd: i32 = @truncate(@as(i64, @bitCast(notif.data.args[0])));
            const stat_buf: *std.os.linux.Stat = @ptrFromInt(stat_ptr);
            break :blk @bitCast(std.os.linux.syscall2(
                .fstat,
                @intCast(fd),
                @intFromPtr(stat_buf),
            ));
        },
        linux.SYS.newfstatat => blk: {
            const dirfd: i32 = @truncate(@as(i64, @bitCast(notif.data.args[0])));
            const path_ptr = notif.data.args[1];
            const flags: u32 = @truncate(notif.data.args[3]);
            const stat_buf: *std.os.linux.Stat = @ptrFromInt(stat_ptr);
            const path_cstr: [*:0]const u8 = @ptrFromInt(path_ptr);
            break :blk @bitCast(std.os.linux.syscall4(
                .newfstatat,
                @intCast(dirfd),
                @intFromPtr(path_cstr),
                @intFromPtr(stat_buf),
                flags,
            ));
        },
        else => return seccomp.continueResponse(notif.id),
    };

    if (result < 0) {
        // Syscall failed, return error
        return seccomp.errorResponse(notif.id, @truncate(-result));
    }

    // Squash timestamps in the stat buffer
    const stat_buf: *std.os.linux.Stat = @ptrFromInt(stat_ptr);
    const squashed_time = timestamp_state.getCurrentTimestamp();

    // Squash atime, mtime, ctime
    stat_buf.atim.sec = squashed_time;
    stat_buf.atim.nsec = 0;
    stat_buf.mtim.sec = squashed_time;
    stat_buf.mtim.nsec = 0;
    stat_buf.ctim.sec = squashed_time;
    stat_buf.ctim.nsec = 0;

    // Normalize uid/gid
    stat_buf.uid = timestamp_mod.normalizeUid(stat_buf.uid);
    stat_buf.gid = timestamp_mod.normalizeGid(stat_buf.gid);

    // Normalize mode
    stat_buf.mode = timestamp_mod.normalizeMode(stat_buf.mode);

    return seccomp.successResponse(notif.id, 0);
}

fn handleAccess(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

/// Handle unlink/unlinkat/rmdir syscalls
/// Create whiteout instead of deleting actual file
///
/// unlink(pathname) -> int
/// unlinkat(dirfd, pathname, flags) -> int
/// rmdir(pathname) -> int
fn handleUnlink(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const syscall_nr = notif.data.nr;

    // Get path pointer based on syscall type
    const path_ptr: u64 = switch (syscall_nr) {
        linux.SYS.unlink, linux.SYS.rmdir => notif.data.args[0],
        linux.SYS.unlinkat => notif.data.args[1],
        else => return seccomp.continueResponse(notif.id),
    };

    if (path_ptr == 0) {
        return seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.FAULT));
    }

    // Read path string (same address space)
    const path_cstr: [*:0]const u8 = @ptrFromInt(path_ptr);
    const path = std.mem.span(path_cstr);

    // Create whiteout instead of deleting
    // This ensures the file appears deleted in overlay but is tracked
    whiteout.deleteFile(ctx.files_dir, path, notif.pid) catch |err| {
        // If whiteout creation fails, return error
        return switch (err) {
            error.MknodFailed => seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.PERM)),
            error.PathTooLong => seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.NAMETOOLONG)),
            else => seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.IO)),
        };
    };

    // Record the deletion in filesystem state
    if (ctx.fs_state) |fs_state| {
        fs_state.recordWrite(path, notif.pid) catch {};
    }

    // Return success (don't actually delete the file)
    return seccomp.successResponse(notif.id, 0);
}

fn handleRename(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleMkdir(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleReadlink(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

/// Handle getdents64 syscall
/// Filter out whiteout entries from directory listings
///
/// getdents64(fd, dirp, count) -> ssize_t
fn handleGetdents(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    _ = ctx;

    const fd: i32 = @truncate(@as(i64, @bitCast(notif.data.args[0])));
    const dirp_ptr = notif.data.args[1];
    const count: usize = @intCast(notif.data.args[2]);

    if (dirp_ptr == 0) {
        return seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.FAULT));
    }

    // Execute the actual syscall
    const result = std.os.linux.syscall3(
        .getdents64,
        @intCast(fd),
        dirp_ptr,
        count,
    );

    const bytes_read: isize = @bitCast(result);
    if (bytes_read < 0) {
        return seccomp.errorResponse(notif.id, @truncate(-bytes_read));
    }

    if (bytes_read == 0) {
        return seccomp.successResponse(notif.id, 0);
    }

    // Filter out whiteout entries
    // dirent64 structure:
    //   d_ino: u64
    //   d_off: i64
    //   d_reclen: u16
    //   d_type: u8
    //   d_name: [...]
    const buf: [*]u8 = @ptrFromInt(dirp_ptr);
    var read_offset: usize = 0;
    var write_offset: usize = 0;

    while (read_offset < @as(usize, @intCast(bytes_read))) {
        const entry_ptr = buf + read_offset;
        const reclen = std.mem.readInt(u16, (entry_ptr + 16)[0..2], .little);

        if (reclen == 0) break; // Safety check

        // Get name (starts at offset 19)
        const name_ptr: [*:0]const u8 = @ptrCast(entry_ptr + 19);
        const name = std.mem.span(name_ptr);

        // Check if this is a whiteout
        if (!whiteout.isWhiteoutName(name)) {
            // Not a whiteout, keep it
            if (write_offset != read_offset) {
                // Move entry to new position
                @memcpy(buf[write_offset .. write_offset + reclen], buf[read_offset .. read_offset + reclen]);
            }
            write_offset += reclen;
        }
        // If it's a whiteout, skip it (don't increment write_offset)

        read_offset += reclen;
    }

    return seccomp.successResponse(notif.id, @intCast(write_offset));
}

fn handleGetcwd(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleChdir(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleChmod(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleChown(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleUtimensat(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

// ============================================================================
// Network syscall handlers
// ============================================================================

fn handleSocket(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    // Redirect to supervisor for network handling
    return seccomp.continueResponse(notif.id);
}

/// Handle connect syscall
/// Redirect connections to loopback IPs through MITM proxy
///
/// connect(sockfd, addr, addrlen) -> int
fn handleConnect(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const net_state = ctx.net_state orelse {
        return seccomp.continueResponse(notif.id);
    };

    if (!net_state.enabled) {
        return seccomp.continueResponse(notif.id);
    }

    const addr_ptr = notif.data.args[1];
    const addrlen: u32 = @truncate(notif.data.args[2]);

    if (addr_ptr == 0 or addrlen < @sizeOf(std.posix.sa_family_t)) {
        return seccomp.continueResponse(notif.id);
    }

    // Read socket address family
    const sa_family: *const std.posix.sa_family_t = @ptrFromInt(addr_ptr);

    // Only handle IPv4 (AF_INET) and IPv6 (AF_INET6) connections
    switch (sa_family.*) {
        std.posix.AF.INET => {
            if (addrlen < @sizeOf(std.posix.sockaddr.in)) {
                return seccomp.continueResponse(notif.id);
            }

            const sockaddr_in: *std.posix.sockaddr.in = @ptrFromInt(addr_ptr);

            // Check if connecting to loopback IP (127.x.x.x)
            const ip_bytes = sockaddr_in.addr;
            const first_byte: u8 = @truncate(ip_bytes);

            if (first_byte == 127) {
                // This is a loopback connection - might be to one of our allocated IPs
                // Format IP as string for lookup
                var ip_str_buf: [16]u8 = undefined;
                const ip_str = std.fmt.bufPrint(&ip_str_buf, "{d}.{d}.{d}.{d}", .{
                    @as(u8, @truncate(ip_bytes)),
                    @as(u8, @truncate(ip_bytes >> 8)),
                    @as(u8, @truncate(ip_bytes >> 16)),
                    @as(u8, @truncate(ip_bytes >> 24)),
                }) catch return seccomp.continueResponse(notif.id);

                // Look up domain for this IP
                if (net_state.getDomainForLoopback(ip_str)) |domain| {
                    // This is a connection to one of our DNS-allocated IPs
                    // The actual connection should be redirected to the proxy
                    // For now, record this and let it continue
                    // Full implementation would modify sockaddr to point to proxy
                    _ = domain;

                    // Log the connection for tracing
                    // In full implementation: redirect to proxy
                }
            }
        },
        std.posix.AF.INET6 => {
            if (addrlen < @sizeOf(std.posix.sockaddr.in6)) {
                return seccomp.continueResponse(notif.id);
            }

            // Similar handling for IPv6
            // Check for ::1:xxxx:xxxx format (our allocated loopback IPs)
        },
        else => {},
    }

    // Let connection proceed
    return seccomp.continueResponse(notif.id);
}

fn handleBind(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleListen(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleAccept(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleSend(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleRecv(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleSockopt(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

fn handleSockname(_: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    return seccomp.continueResponse(notif.id);
}

// ============================================================================
// Random syscall handlers
// ============================================================================

/// Handle getrandom syscall - provide reproducible random bytes
/// getrandom(buf, buflen, flags) -> ssize_t
///
/// Since we share address space with target (CLONE_VM), we can write
/// directly to the buffer pointer.
fn handleGetrandom(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const prng_state = ctx.prng_state orelse {
        // No PRNG state, let syscall proceed normally
        return seccomp.continueResponse(notif.id);
    };

    const buf_ptr = notif.data.args[0]; // Buffer pointer (same address space!)
    const buflen = notif.data.args[1]; // Buffer length
    // flags = notif.data.args[2] (ignored for reproducibility)

    if (buflen == 0 or buf_ptr == 0) {
        return seccomp.successResponse(notif.id, 0);
    }

    // Limit buffer size
    const max_buflen: usize = 256;
    const actual_len: usize = @min(@as(usize, @intCast(buflen)), max_buflen);

    // Direct access to target's buffer (same address space via CLONE_VM)
    const buf: [*]u8 = @ptrFromInt(buf_ptr);

    // Generate reproducible random bytes directly into target's buffer
    prng_state.fillBytes(notif.pid, buf[0..actual_len]);

    // Return bytes written (don't execute actual syscall)
    return seccomp.successResponse(notif.id, @intCast(actual_len));
}

// ============================================================================
// Time syscall handlers
// ============================================================================

/// Handle clock_gettime syscall - provide deterministic time
/// clock_gettime(clockid, *timespec) -> int
fn handleClockGettime(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const time_state = ctx.time_state orelse {
        return seccomp.continueResponse(notif.id);
    };

    const clockid = notif.data.args[0];
    const ts_ptr = notif.data.args[1];

    // Only intercept CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1)
    if (clockid != 0 and clockid != 1) {
        return seccomp.continueResponse(notif.id);
    }

    if (ts_ptr == 0) {
        return seccomp.errorResponse(notif.id, @intFromEnum(std.os.linux.E.FAULT));
    }

    // Direct access to target's timespec (same address space)
    const ts: *std.os.linux.timespec = @ptrFromInt(ts_ptr);
    const result = time_state.getTimespec();
    ts.* = result;

    return seccomp.successResponse(notif.id, 0);
}

/// Handle gettimeofday syscall - provide deterministic time
/// gettimeofday(*timeval, *timezone) -> int
fn handleGettimeofday(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const time_state = ctx.time_state orelse {
        return seccomp.continueResponse(notif.id);
    };

    const tv_ptr = notif.data.args[0];
    // timezone (args[1]) is usually NULL and deprecated

    if (tv_ptr == 0) {
        return seccomp.successResponse(notif.id, 0);
    }

    // Direct access to target's timeval (same address space)
    const tv: *std.os.linux.timeval = @ptrFromInt(tv_ptr);
    tv.* = time_state.getTimeval();

    return seccomp.successResponse(notif.id, 0);
}

/// Handle time syscall - provide deterministic time
/// time(*time_t) -> time_t
fn handleTimeSyscall(ctx: *HandlerContext, notif: *const linux.SeccompNotif) linux.SeccompNotifResp {
    const time_state = ctx.time_state orelse {
        return seccomp.continueResponse(notif.id);
    };

    const t_ptr = notif.data.args[0];
    const t = time_state.getTime();

    // If pointer is non-null, write to it (same address space)
    if (t_ptr != 0) {
        const t_dest: *i64 = @ptrFromInt(t_ptr);
        t_dest.* = t;
    }

    // Return time value
    return seccomp.successResponse(notif.id, t);
}

// ============================================================================
// Tests
// ============================================================================

test "handler context initialization" {
    const allocator = std.testing.allocator;
    const ctx = HandlerContext{
        .allocator = allocator,
        .seccomp_fd = -1,
    };
    try std.testing.expect(ctx.fs_state == null);
    try std.testing.expect(ctx.prng_state == null);
    try std.testing.expect(ctx.time_state == null);
}

test "getrandom handler with prng - null buffer" {
    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.getrandom,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, 16, 0, 0, 0, 0 }, // buf=NULL, len=16
        },
    };

    var prng_state = prng.HierarchicalPrng.init(12345);
    defer prng_state.deinit();

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .prng_state = &prng_state,
    };

    const resp = handleGetrandom(&ctx, &notif);
    // Should return 0 for null buffer
    try std.testing.expectEqual(@as(i64, 0), resp.val);
}

test "getrandom handler without prng" {
    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.getrandom,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0x1000, 16, 0, 0, 0, 0 },
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .prng_state = null, // No PRNG
    };

    const resp = handleGetrandom(&ctx, &notif);
    // Should return CONTINUE flag when no PRNG state
    try std.testing.expectEqual(linux.SECCOMP_USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "time handler with null pointer" {
    var time_state = time_mod.DeterministicTime.initWithTime(1700000000);

    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.time,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, 0, 0, 0, 0, 0 }, // NULL pointer
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .time_state = &time_state,
    };

    const resp = handleTimeSyscall(&ctx, &notif);
    // Should return deterministic time value
    try std.testing.expectEqual(@as(i64, 1700000000), resp.val);
    try std.testing.expectEqual(@as(i32, 0), resp.@"error");
    try std.testing.expectEqual(@as(u32, 0), resp.flags); // Not CONTINUE
}

test "prng reproducibility across calls" {
    var prng_state = prng.HierarchicalPrng.init(12345);
    defer prng_state.deinit();

    var buf1: [16]u8 = undefined;
    var buf2: [16]u8 = undefined;

    prng_state.fillBytes(1, &buf1);

    // Reset with same seed
    var prng_state2 = prng.HierarchicalPrng.init(12345);
    defer prng_state2.deinit();

    prng_state2.fillBytes(1, &buf2);

    // Should be identical
    try std.testing.expectEqualSlices(u8, &buf1, &buf2);
}

test "time state determinism" {
    var time_state = time_mod.DeterministicTime.initWithTime(1700000000);

    const t1 = time_state.getTime();
    const t2 = time_state.getTime();

    // Frozen mode: times should be equal
    try std.testing.expectEqual(t1, t2);
    try std.testing.expectEqual(@as(i64, 1700000000), t1);
}

test "timestamp normalization" {
    // Test normalizeUid
    try std.testing.expectEqual(@as(u32, 1000), timestamp_mod.normalizeUid(0));
    try std.testing.expectEqual(@as(u32, 1000), timestamp_mod.normalizeUid(501));

    // Test normalizeGid
    try std.testing.expectEqual(@as(u32, 1000), timestamp_mod.normalizeGid(0));
    try std.testing.expectEqual(@as(u32, 1000), timestamp_mod.normalizeGid(20));

    // Test normalizeMode - directory
    try std.testing.expectEqual(
        std.os.linux.S.IFDIR | 0o755,
        timestamp_mod.normalizeMode(std.os.linux.S.IFDIR | 0o777),
    );

    // Test normalizeMode - regular file (non-executable)
    try std.testing.expectEqual(
        std.os.linux.S.IFREG | 0o644,
        timestamp_mod.normalizeMode(std.os.linux.S.IFREG | 0o600),
    );

    // Test normalizeMode - executable file
    try std.testing.expectEqual(
        std.os.linux.S.IFREG | 0o755,
        timestamp_mod.normalizeMode(std.os.linux.S.IFREG | 0o700),
    );
}

test "whiteout name detection" {
    try std.testing.expect(whiteout.isWhiteoutName(".wh.deleted_file"));
    try std.testing.expect(!whiteout.isWhiteoutName("normal_file"));
    try std.testing.expect(!whiteout.isWhiteoutName(".hidden_file"));

    try std.testing.expectEqualStrings(
        "deleted_file",
        whiteout.getOriginalName(".wh.deleted_file"),
    );
}

test "special path detection" {
    try std.testing.expectEqual(remap.SpecialPath.ca_certificates, remap.getSpecialPath("/etc/ssl/certs/ca-certificates.crt"));
    try std.testing.expectEqual(remap.SpecialPath.resolv_conf, remap.getSpecialPath("/etc/resolv.conf"));
    try std.testing.expectEqual(remap.SpecialPath.dev_urandom, remap.getSpecialPath("/dev/urandom"));
    try std.testing.expectEqual(remap.SpecialPath.dev_random, remap.getSpecialPath("/dev/random"));
    try std.testing.expectEqual(remap.SpecialPath.proc_self, remap.getSpecialPath("/proc/self/exe"));
    try std.testing.expectEqual(remap.SpecialPath.none, remap.getSpecialPath("/usr/bin/ls"));
}

test "open handler without fs_state continues" {
    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.open,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, 0, 0, 0, 0, 0 }, // NULL path
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .fs_state = null,
    };

    const resp = handleOpen(&ctx, &notif);
    // Should return EFAULT for null path
    try std.testing.expectEqual(@as(i32, -@as(i32, @intFromEnum(std.os.linux.E.FAULT))), resp.@"error");
}

test "connect handler without net_state continues" {
    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.connect,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 3, 0, 16, 0, 0, 0 }, // fd=3, addr=NULL, len=16
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .net_state = null,
    };

    const resp = handleConnect(&ctx, &notif);
    // Should return CONTINUE when no net_state
    try std.testing.expectEqual(linux.SECCOMP_USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "unlink handler with null path" {
    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.unlink,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, 0, 0, 0, 0, 0 }, // NULL path
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .fs_state = null,
    };

    const resp = handleUnlink(&ctx, &notif);
    // Should return EFAULT for null path
    try std.testing.expectEqual(@as(i32, -@as(i32, @intFromEnum(std.os.linux.E.FAULT))), resp.@"error");
}

test "clock_gettime handler without time_state continues" {
    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.clock_gettime,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, 0x1000, 0, 0, 0, 0 }, // CLOCK_REALTIME, ts ptr
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .time_state = null,
    };

    const resp = handleClockGettime(&ctx, &notif);
    // Should return CONTINUE when no time_state
    try std.testing.expectEqual(linux.SECCOMP_USER_NOTIF_FLAG_CONTINUE, resp.flags);
}

test "clock_gettime handler with null pointer" {
    var time_state = time_mod.DeterministicTime.initWithTime(1700000000);

    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.clock_gettime,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, 0, 0, 0, 0, 0 }, // CLOCK_REALTIME, ts=NULL
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .time_state = &time_state,
    };

    const resp = handleClockGettime(&ctx, &notif);
    // Should return EFAULT for null pointer
    try std.testing.expectEqual(@as(i32, -@as(i32, @intFromEnum(std.os.linux.E.FAULT))), resp.@"error");
}

test "gettimeofday handler with null pointer" {
    var time_state = time_mod.DeterministicTime.initWithTime(1700000000);

    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.gettimeofday,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, 0, 0, 0, 0, 0 }, // tv=NULL, tz=NULL
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .time_state = &time_state,
    };

    const resp = handleGettimeofday(&ctx, &notif);
    // Should return success with null pointer (valid behavior)
    try std.testing.expectEqual(@as(i64, 0), resp.val);
    try std.testing.expectEqual(@as(i32, 0), resp.@"error");
}

// ============================================================================
// Functional Tests - Verify handlers WORK, not just that they fail correctly
// ============================================================================

test "executeOpen actually opens a file" {
    // Create a temp file
    const tmp_path = "/tmp/uwrx_test_open_file.txt";
    const content = "test content for executeOpen";

    // Write test file
    const write_file = try std.fs.createFileAbsolute(tmp_path, .{});
    try write_file.writeAll(content);
    write_file.close();
    defer std.fs.deleteFileAbsolute(tmp_path) catch {};

    // Test executeOpen
    const result = executeOpen(tmp_path, 0, 0); // O_RDONLY
    try std.testing.expect(result >= 0); // Should return valid fd

    // Read from the fd and verify content
    const fd: std.posix.fd_t = @intCast(result);
    defer std.posix.close(fd);

    var buf: [100]u8 = undefined;
    const bytes_read = try std.posix.read(fd, &buf);
    try std.testing.expectEqualStrings(content, buf[0..bytes_read]);
}

test "executeOpen returns error for nonexistent file" {
    const result = executeOpen("/nonexistent/path/to/file.txt", 0, 0);
    try std.testing.expect(result < 0); // Should return negative error
    try std.testing.expectEqual(-@as(i64, @intFromEnum(std.os.linux.E.NOENT)), result);
}

test "getrandom handler fills buffer with reproducible data" {
    const allocator = std.testing.allocator;

    // Create two PRNG states with same seed
    var prng_state1 = prng.HierarchicalPrng.init(0xDEADBEEF);
    defer prng_state1.deinit();

    var prng_state2 = prng.HierarchicalPrng.init(0xDEADBEEF);
    defer prng_state2.deinit();

    // Allocate buffer in our address space
    var buf1: [32]u8 = undefined;
    var buf2: [32]u8 = undefined;

    // Create notification pointing to our buffer
    const notif1 = linux.SeccompNotif{
        .id = 1,
        .pid = 1,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.getrandom,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ @intFromPtr(&buf1), 32, 0, 0, 0, 0 },
        },
    };

    const notif2 = linux.SeccompNotif{
        .id = 2,
        .pid = 1,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.getrandom,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ @intFromPtr(&buf2), 32, 0, 0, 0, 0 },
        },
    };

    var ctx1 = HandlerContext{
        .allocator = allocator,
        .seccomp_fd = -1,
        .prng_state = &prng_state1,
    };

    var ctx2 = HandlerContext{
        .allocator = allocator,
        .seccomp_fd = -1,
        .prng_state = &prng_state2,
    };

    // Call handlers - they should write directly to buf1/buf2
    const resp1 = handleGetrandom(&ctx1, &notif1);
    const resp2 = handleGetrandom(&ctx2, &notif2);

    // Both should succeed with 32 bytes
    try std.testing.expectEqual(@as(i64, 32), resp1.val);
    try std.testing.expectEqual(@as(i64, 32), resp2.val);
    try std.testing.expectEqual(@as(u32, 0), resp1.flags); // Not CONTINUE
    try std.testing.expectEqual(@as(u32, 0), resp2.flags);

    // Buffers should be identical (same seed, same pid)
    try std.testing.expectEqualSlices(u8, &buf1, &buf2);

    // Buffers should not be all zeros (actually random)
    var all_zero = true;
    for (buf1) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "clock_gettime handler writes to timespec buffer" {
    var time_state = time_mod.DeterministicTime.initWithTime(1700000000);

    // Allocate timespec in our address space
    var ts: std.os.linux.timespec = undefined;

    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.clock_gettime,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ 0, @intFromPtr(&ts), 0, 0, 0, 0 }, // CLOCK_REALTIME
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .time_state = &time_state,
    };

    const resp = handleClockGettime(&ctx, &notif);

    // Should succeed
    try std.testing.expectEqual(@as(i64, 0), resp.val);
    try std.testing.expectEqual(@as(i32, 0), resp.@"error");
    try std.testing.expectEqual(@as(u32, 0), resp.flags); // Not CONTINUE

    // timespec should have the deterministic time
    try std.testing.expectEqual(@as(isize, 1700000000), ts.sec);
    try std.testing.expectEqual(@as(isize, 0), ts.nsec);
}

test "gettimeofday handler writes to timeval buffer" {
    var time_state = time_mod.DeterministicTime.initWithTime(1700000000);

    // Allocate timeval in our address space
    var tv: std.os.linux.timeval = undefined;

    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.gettimeofday,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ @intFromPtr(&tv), 0, 0, 0, 0, 0 },
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .time_state = &time_state,
    };

    const resp = handleGettimeofday(&ctx, &notif);

    // Should succeed
    try std.testing.expectEqual(@as(i64, 0), resp.val);
    try std.testing.expectEqual(@as(i32, 0), resp.@"error");
    try std.testing.expectEqual(@as(u32, 0), resp.flags); // Not CONTINUE

    // timeval should have the deterministic time
    try std.testing.expectEqual(@as(isize, 1700000000), tv.sec);
    try std.testing.expectEqual(@as(isize, 0), tv.usec);
}

test "time syscall handler writes and returns time" {
    var time_state = time_mod.DeterministicTime.initWithTime(1700000000);

    // Allocate time_t in our address space
    var t: i64 = undefined;

    const notif = linux.SeccompNotif{
        .id = 12345,
        .pid = 1000,
        .flags = 0,
        .data = .{
            .nr = linux.SYS.time,
            .arch = linux.auditArch(),
            .instruction_pointer = 0,
            .args = .{ @intFromPtr(&t), 0, 0, 0, 0, 0 },
        },
    };

    var ctx = HandlerContext{
        .allocator = std.testing.allocator,
        .seccomp_fd = -1,
        .time_state = &time_state,
    };

    const resp = handleTimeSyscall(&ctx, &notif);

    // Should return the time value
    try std.testing.expectEqual(@as(i64, 1700000000), resp.val);
    try std.testing.expectEqual(@as(i32, 0), resp.@"error");
    try std.testing.expectEqual(@as(u32, 0), resp.flags); // Not CONTINUE

    // t should also be written
    try std.testing.expectEqual(@as(i64, 1700000000), t);
}

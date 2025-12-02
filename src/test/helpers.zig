//! Helper programs for testing
//!
//! Provides small test programs that can be used to verify uwrx functionality.
//! These are shell scripts that can be written to temp files and executed.

const std = @import("std");

/// Helper script that echoes its arguments
pub const echo_args =
    \\#!/bin/sh
    \\echo "ARGS: $@"
    \\exit 0
;

/// Helper script that exits with a specific code
pub const exit_code =
    \\#!/bin/sh
    \\exit ${1:-0}
;

/// Helper script that writes to a file
pub const write_file =
    \\#!/bin/sh
    \\FILE="$1"
    \\CONTENT="$2"
    \\echo "$CONTENT" > "$FILE"
    \\exit 0
;

/// Helper script that reads a file
pub const read_file =
    \\#!/bin/sh
    \\FILE="$1"
    \\if [ -f "$FILE" ]; then
    \\    cat "$FILE"
    \\    exit 0
    \\else
    \\    echo "File not found: $FILE" >&2
    \\    exit 1
    \\fi
;

/// Helper script that checks file existence
pub const file_exists =
    \\#!/bin/sh
    \\if [ -e "$1" ]; then
    \\    echo "EXISTS"
    \\    exit 0
    \\else
    \\    echo "NOT_EXISTS"
    \\    exit 1
    \\fi
;

/// Helper script that prints current time
pub const print_time =
    \\#!/bin/sh
    \\date +%s
;

/// Helper script that generates random bytes (uses /dev/urandom)
pub const random_bytes =
    \\#!/bin/sh
    \\N=${1:-16}
    \\head -c "$N" /dev/urandom | od -An -tx1 | tr -d ' \n'
    \\echo
;

/// Helper script that makes an HTTP request (uses curl if available)
pub const http_get =
    \\#!/bin/sh
    \\URL="$1"
    \\if command -v curl >/dev/null 2>&1; then
    \\    curl -s "$URL"
    \\elif command -v wget >/dev/null 2>&1; then
    \\    wget -q -O - "$URL"
    \\else
    \\    echo "No HTTP client available" >&2
    \\    exit 1
    \\fi
;

/// Helper script that creates a process tree
pub const fork_tree =
    \\#!/bin/sh
    \\# Create a small process tree for testing
    \\DEPTH=${1:-2}
    \\ID=${2:-root}
    \\
    \\echo "PROCESS: $ID (pid=$$)"
    \\
    \\if [ "$DEPTH" -gt 0 ]; then
    \\    NEXT_DEPTH=$((DEPTH - 1))
    \\    $0 "$NEXT_DEPTH" "${ID}_left" &
    \\    $0 "$NEXT_DEPTH" "${ID}_right" &
    \\    wait
    \\fi
    \\exit 0
;

/// Helper script that modifies files
pub const file_modifier =
    \\#!/bin/sh
    \\# Create, modify, and delete files
    \\DIR="$1"
    \\mkdir -p "$DIR"
    \\echo "created" > "$DIR/created.txt"
    \\echo "will_modify" > "$DIR/modified.txt"
    \\echo "will_delete" > "$DIR/deleted.txt"
    \\
    \\# Modify
    \\echo "modified_content" > "$DIR/modified.txt"
    \\
    \\# Delete
    \\rm "$DIR/deleted.txt"
    \\
    \\echo "FILES:"
    \\ls -la "$DIR"
;

/// Helper script that reads environment
pub const env_reader =
    \\#!/bin/sh
    \\# Print specific env vars for testing
    \\echo "PATH=$PATH"
    \\echo "HOME=$HOME"
    \\echo "USER=$USER"
    \\echo "UWRX_TEST=${UWRX_TEST:-unset}"
;

/// Helper that performs a long-running task
pub const long_running =
    \\#!/bin/sh
    \\SECONDS=${1:-5}
    \\echo "Starting long task for $SECONDS seconds"
    \\sleep "$SECONDS"
    \\echo "Completed"
    \\exit 0
;

/// Helper that produces structured output
pub const structured_output =
    \\#!/bin/sh
    \\echo "HEADER: test output"
    \\echo "LINE1: first line"
    \\echo "LINE2: second line"
    \\echo "LINE3: third line"
    \\echo "FOOTER: end of output"
;

/// Create a helper script in the given directory
pub fn createHelper(allocator: std.mem.Allocator, dir: []const u8, name: []const u8, content: []const u8) ![]const u8 {
    const path = try std.fs.path.join(allocator, &.{ dir, name });
    errdefer allocator.free(path);

    const file = try std.fs.createFileAbsolute(path, .{});
    defer file.close();

    try file.writeAll(content);

    // Make executable
    try std.posix.fchmod(file.handle, 0o755);

    return path;
}

/// Helper that writes to stdout and stderr
pub const mixed_output =
    \\#!/bin/sh
    \\echo "stdout line 1"
    \\echo "stderr line 1" >&2
    \\echo "stdout line 2"
    \\echo "stderr line 2" >&2
;

/// Helper that spawns multiple children and collects exit codes
pub const multi_child =
    \\#!/bin/sh
    \\NUM=${1:-3}
    \\FAIL_IDX=${2:-0}
    \\
    \\for i in $(seq 1 $NUM); do
    \\    if [ "$i" = "$FAIL_IDX" ]; then
    \\        (exit 1) &
    \\    else
    \\        (sleep 0.1; exit 0) &
    \\    fi
    \\done
    \\wait
    \\echo "All children completed"
;

/// Helper that tests file permissions
pub const permission_test =
    \\#!/bin/sh
    \\FILE="$1"
    \\
    \\# Test read
    \\if cat "$FILE" > /dev/null 2>&1; then
    \\    echo "READ: OK"
    \\else
    \\    echo "READ: FAIL"
    \\fi
    \\
    \\# Test write
    \\if echo "test" >> "$FILE" 2>/dev/null; then
    \\    echo "WRITE: OK"
    \\else
    \\    echo "WRITE: FAIL"
    \\fi
;

/// Inline C program that can be compiled - prints hello
pub const c_hello =
    \\#include <stdio.h>
    \\int main() {
    \\    printf("Hello from C!\n");
    \\    return 0;
    \\}
;

/// Inline C program that reads /proc/self/exe
pub const c_self_exe =
    \\#include <stdio.h>
    \\#include <unistd.h>
    \\int main() {
    \\    char buf[4096];
    \\    ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf)-1);
    \\    if (len > 0) {
    \\        buf[len] = '\0';
    \\        printf("Self: %s\n", buf);
    \\        return 0;
    \\    }
    \\    return 1;
    \\}
;

test "createHelper" {
    const allocator = std.testing.allocator;

    const path = try createHelper(allocator, "/tmp", "test_helper.sh", echo_args);
    defer allocator.free(path);
    defer std.fs.deleteFileAbsolute(path) catch {};

    // Check it exists and is executable
    const stat = try std.fs.cwd().statFile(path);
    try std.testing.expect(stat.mode & 0o111 != 0);
}

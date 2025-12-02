//! Bundle format and section parsing
//!
//! Defines the ELF section format for bundled content:
//!   .uwrx.exec.<name> - bundled executable code and data
//!   .uwrx.data.<name> - compressed filesystem overlay

const std = @import("std");
const mod = @import("mod.zig");
const elf = @import("../manager/elf.zig");

/// Section name prefixes
pub const EXEC_PREFIX = ".uwrx.exec.";
pub const DATA_PREFIX = ".uwrx.data.";

/// Bundle header at start of each section
pub const BundleHeader = extern struct {
    magic: [8]u8, // "UWRXBNDL"
    version: u32,
    entry_offset: u32,
    flags: u32,
    reserved: [12]u8,
};

pub const BUNDLE_MAGIC = "UWRXBNDL".*;
pub const BUNDLE_VERSION: u32 = 1;

/// Load bundled sections from own executable
pub fn loadBundledSections(state: *mod.BundleState) !void {
    // Read own executable
    const self_path = "/proc/self/exe";
    const file = try std.fs.openFileAbsolute(self_path, .{});
    defer file.close();

    // Parse ELF
    var ehdr: elf.Elf64_Ehdr = undefined;
    const ehdr_bytes = std.mem.asBytes(&ehdr);
    _ = try file.readAll(ehdr_bytes);

    // Verify ELF
    if (!std.mem.eql(u8, ehdr.e_ident[0..4], &elf.ELF_MAGIC)) {
        return error.InvalidElf;
    }

    // Read section headers
    if (ehdr.e_shoff == 0 or ehdr.e_shnum == 0) {
        return; // No sections
    }

    try file.seekTo(ehdr.e_shoff);

    const shdrs = try state.allocator.alloc(elf.Elf64_Shdr, ehdr.e_shnum);
    defer state.allocator.free(shdrs);

    const shdrs_bytes = std.mem.sliceAsBytes(shdrs);
    _ = try file.readAll(shdrs_bytes);

    // Read section name string table
    if (ehdr.e_shstrndx >= ehdr.e_shnum) {
        return; // Invalid string table index
    }

    const strtab_shdr = shdrs[ehdr.e_shstrndx];
    var strtab = try state.allocator.alloc(u8, @intCast(strtab_shdr.sh_size));
    defer state.allocator.free(strtab);

    try file.seekTo(strtab_shdr.sh_offset);
    _ = try file.readAll(strtab);

    // Find bundled sections
    for (shdrs) |shdr| {
        if (shdr.sh_name >= strtab.len) continue;

        const name_start = shdr.sh_name;
        var name_end = name_start;
        while (name_end < strtab.len and strtab[name_end] != 0) {
            name_end += 1;
        }
        const section_name = strtab[name_start..name_end];

        if (std.mem.startsWith(u8, section_name, EXEC_PREFIX)) {
            const exec_name = section_name[EXEC_PREFIX.len..];
            try loadExecSection(state, file, shdr, exec_name);
        } else if (std.mem.startsWith(u8, section_name, DATA_PREFIX)) {
            const data_name = section_name[DATA_PREFIX.len..];
            try loadDataSection(state, shdr, data_name);
        }
    }
}

fn loadExecSection(state: *mod.BundleState, file: std.fs.File, shdr: elf.Elf64_Shdr, name: []const u8) !void {
    // Read header
    try file.seekTo(shdr.sh_offset);

    var header: BundleHeader = undefined;
    const header_bytes = std.mem.asBytes(&header);
    _ = try file.readAll(header_bytes);

    // Verify magic
    if (!std.mem.eql(u8, &header.magic, &BUNDLE_MAGIC)) {
        return error.InvalidBundleHeader;
    }

    const name_copy = try state.allocator.dupe(u8, name);

    try state.executables.put(name_copy, .{
        .name = name_copy,
        .offset = @intCast(shdr.sh_offset + @sizeOf(BundleHeader)),
        .size = @intCast(shdr.sh_size - @sizeOf(BundleHeader)),
        .entry_offset = header.entry_offset,
    });
}

fn loadDataSection(state: *mod.BundleState, shdr: elf.Elf64_Shdr, name: []const u8) !void {
    const name_copy = try state.allocator.dupe(u8, name);

    try state.data_overlays.put(name_copy, .{
        .name = name_copy,
        .offset = @intCast(shdr.sh_offset),
        .size = @intCast(shdr.sh_size),
        .compression = .squashfs, // Default
    });
}

test "bundle header size" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(BundleHeader));
}

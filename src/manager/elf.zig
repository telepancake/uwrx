//! ELF parsing and loading
//!
//! Parses ELF executables to extract program headers, find the interpreter,
//! and load segments into memory.

const std = @import("std");

/// ELF header (64-bit)
pub const Elf64_Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

/// Program header (64-bit)
pub const Elf64_Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

/// Section header (64-bit)
pub const Elf64_Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

/// ELF magic bytes
pub const ELF_MAGIC = [4]u8{ 0x7f, 'E', 'L', 'F' };

/// ELF class
pub const ELFCLASS64 = 2;

/// ELF data encoding
pub const ELFDATA2LSB = 1; // Little endian

/// ELF types
pub const ET_EXEC = 2;
pub const ET_DYN = 3;

/// Program header types
pub const PT_NULL = 0;
pub const PT_LOAD = 1;
pub const PT_DYNAMIC = 2;
pub const PT_INTERP = 3;
pub const PT_NOTE = 4;
pub const PT_SHLIB = 5;
pub const PT_PHDR = 6;
pub const PT_TLS = 7;
pub const PT_GNU_EH_FRAME = 0x6474e550;
pub const PT_GNU_STACK = 0x6474e551;
pub const PT_GNU_RELRO = 0x6474e552;

/// Program header flags
pub const PF_X = 1;
pub const PF_W = 2;
pub const PF_R = 4;

/// Relocation types (x86_64)
pub const R_X86_64_NONE = 0;
pub const R_X86_64_64 = 1;
pub const R_X86_64_RELATIVE = 8;
pub const R_X86_64_GLOB_DAT = 6;
pub const R_X86_64_JUMP_SLOT = 7;

/// Loaded executable information
pub const ExecutableInfo = struct {
    allocator: std.mem.Allocator,
    /// Path to the executable
    path: []const u8,
    /// ELF header
    ehdr: Elf64_Ehdr,
    /// Program headers
    phdrs: []Elf64_Phdr,
    /// Interpreter path (from PT_INTERP)
    interp: ?[]u8,
    /// Entry point address
    entry: u64,
    /// Whether this is a PIE (position-independent executable)
    is_pie: bool,

    pub fn deinit(self: *ExecutableInfo) void {
        self.allocator.free(self.phdrs);
        if (self.interp) |i| {
            self.allocator.free(i);
        }
    }
};

/// Load and parse an ELF executable
pub fn loadExecutable(allocator: std.mem.Allocator, path: []const u8) !ExecutableInfo {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    // Read ELF header
    var ehdr: Elf64_Ehdr = undefined;
    const ehdr_bytes = std.mem.asBytes(&ehdr);
    const bytes_read = try file.readAll(ehdr_bytes);
    if (bytes_read != @sizeOf(Elf64_Ehdr)) {
        return error.InvalidElf;
    }

    // Verify magic
    if (!std.mem.eql(u8, ehdr.e_ident[0..4], &ELF_MAGIC)) {
        return error.InvalidElf;
    }

    // Verify 64-bit
    if (ehdr.e_ident[4] != ELFCLASS64) {
        return error.Not64Bit;
    }

    // Verify little-endian
    if (ehdr.e_ident[5] != ELFDATA2LSB) {
        return error.NotLittleEndian;
    }

    // Read program headers
    const phdrs = try allocator.alloc(Elf64_Phdr, ehdr.e_phnum);
    errdefer allocator.free(phdrs);

    try file.seekTo(ehdr.e_phoff);
    const phdrs_bytes = std.mem.sliceAsBytes(phdrs);
    const phdr_bytes_read = try file.readAll(phdrs_bytes);
    if (phdr_bytes_read != phdrs_bytes.len) {
        return error.InvalidElf;
    }

    // Find interpreter
    var interp: ?[]u8 = null;
    for (phdrs) |phdr| {
        if (phdr.p_type == PT_INTERP) {
            interp = try allocator.alloc(u8, @intCast(phdr.p_filesz - 1)); // -1 for null terminator
            errdefer allocator.free(interp.?);

            try file.seekTo(phdr.p_offset);
            const interp_read = try file.readAll(interp.?);
            if (interp_read != interp.?.len) {
                return error.InvalidElf;
            }
            break;
        }
    }

    return .{
        .allocator = allocator,
        .path = path,
        .ehdr = ehdr,
        .phdrs = phdrs,
        .interp = interp,
        .entry = ehdr.e_entry,
        .is_pie = ehdr.e_type == ET_DYN,
    };
}

/// Load ELF segments into memory
pub fn loadSegments(
    allocator: std.mem.Allocator,
    file: std.fs.File,
    phdrs: []const Elf64_Phdr,
    base_addr: u64,
) !void {
    _ = allocator;

    for (phdrs) |phdr| {
        if (phdr.p_type != PT_LOAD) continue;

        const vaddr = base_addr + phdr.p_vaddr;
        const memsz = phdr.p_memsz;
        const filesz = phdr.p_filesz;

        // Calculate page-aligned values
        const page_size: u64 = 4096;
        const page_offset = vaddr % page_size;
        const aligned_vaddr = vaddr - page_offset;
        const aligned_memsz = std.mem.alignForward(u64, memsz + page_offset, page_size);

        // Map memory
        const prot: u32 = (if (phdr.p_flags & PF_R != 0) std.os.linux.PROT.READ else 0) |
            (if (phdr.p_flags & PF_W != 0) std.os.linux.PROT.WRITE else 0) |
            (if (phdr.p_flags & PF_X != 0) std.os.linux.PROT.EXEC else 0);

        const map_result = std.os.linux.mmap(
            @ptrFromInt(aligned_vaddr),
            aligned_memsz,
            prot | std.os.linux.PROT.WRITE, // Need write for initial load
            .{ .TYPE = .PRIVATE, .ANONYMOUS = true, .FIXED = true },
            -1,
            0,
        );

        if (map_result == std.os.linux.MAP_FAILED) {
            return error.MmapFailed;
        }

        // Read file contents
        if (filesz > 0) {
            try file.seekTo(phdr.p_offset);
            const dest: [*]u8 = @ptrFromInt(vaddr);
            _ = try file.readAll(dest[0..@intCast(filesz)]);
        }

        // Zero BSS
        if (memsz > filesz) {
            const bss_start: [*]u8 = @ptrFromInt(vaddr + filesz);
            @memset(bss_start[0..@intCast(memsz - filesz)], 0);
        }

        // Set final protection if we added WRITE
        if (phdr.p_flags & PF_W == 0) {
            _ = std.os.linux.mprotect(
                @ptrFromInt(aligned_vaddr),
                aligned_memsz,
                prot,
            );
        }
    }
}

/// Calculate total memory span needed for loaded segments
pub fn calculateLoadSpan(phdrs: []const Elf64_Phdr) struct { min: u64, max: u64 } {
    var min: u64 = std.math.maxInt(u64);
    var max: u64 = 0;

    for (phdrs) |phdr| {
        if (phdr.p_type != PT_LOAD) continue;
        if (phdr.p_vaddr < min) min = phdr.p_vaddr;
        if (phdr.p_vaddr + phdr.p_memsz > max) max = phdr.p_vaddr + phdr.p_memsz;
    }

    return .{ .min = min, .max = max };
}

test "ELF magic detection" {
    try std.testing.expectEqual(@as(u8, 0x7f), ELF_MAGIC[0]);
    try std.testing.expectEqual(@as(u8, 'E'), ELF_MAGIC[1]);
    try std.testing.expectEqual(@as(u8, 'L'), ELF_MAGIC[2]);
    try std.testing.expectEqual(@as(u8, 'F'), ELF_MAGIC[3]);
}

test "struct sizes" {
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(Elf64_Ehdr));
    try std.testing.expectEqual(@as(usize, 56), @sizeOf(Elf64_Phdr));
}

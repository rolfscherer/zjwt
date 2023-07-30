const std = @import("std");

const bte = @import("big_token_example.zig");
const ece = @import("ecdsa_example.zig");

pub fn execExamples(allocator: std.mem.Allocator) !void {
    try bte.encodeAndDecode(allocator);
    try ece.encodeAndDecodeAll(allocator);
}

const std = @import("std");
const zjwt = @import("zjwt");
const mem = std.mem;

const parser = zjwt.parser;
const utils = zjwt.utils;

var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 12 }){};
const allocator = gpa.allocator();

pub fn main() !void {
    var p = parser.Parser.init(allocator);
    defer p.deinit();

    //const content = try utils.readFileRelative("src/zjwt/asn1/certs/secp384r1_private_key.pem", allocator);
    const content = try utils.readFileRelative("src/zjwt/asn1/certs/secp384r1_key.pem", allocator);
    defer content.deinit();

    try p.parsePEM(content.items);
}

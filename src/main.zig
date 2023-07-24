const std = @import("std");
const str = @import("string.zig");
const utils = @import("utils.zig");

const Jwt = @import("jwt.zig").Jwt;
const Algorithm = @import("jwt.zig").Algorithm;

var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 12 }){};
const allocator = gpa.allocator();

pub fn main() !void {
    var jwt = Jwt.init(allocator);
    defer jwt.deinit();

    try jwt.addIssuer("Allerate");
    try jwt.addSubject("Jwt");
    try jwt.addIssuedAt();
    try jwt.addExpiresAt(utils.getSecondsFromDays(1));
    try jwt.addPayload("name", .{ .string = "John Allerate" });
    try jwt.addPayload("admin", .{ .bool = true });

    const token = try jwt.encode(Algorithm.HS512, .{ .key = "veryS3cret:-)" });

    std.log.info("{s}", .{token.str()});

    try jwt.addExpiresAtValidator();
    try jwt.decode(Algorithm.HS512, .{ .key = "veryS3cret:-)" }, token.str());
}

test "all tests" {
    _ = @import("string.zig");
    _ = @import("jwt.zig");
    _ = @import("claims.zig");
}

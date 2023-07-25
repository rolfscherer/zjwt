const std = @import("std");
const utils = @import("jwt/utils.zig");

const jwt = @import("jwt.zig").Jwt;
const Jwt = jwt.Jwt;
const Algorithm = jwt.Algorithm;
const Value = std.json.Value;

var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 12 }){};
const allocator = gpa.allocator();

pub fn main() !void {
    var j = Jwt.init(allocator);

    var token = jwt.Token.init(allocator);
    defer token.deinit();

    try token.createDefaultHeader(jwt.Algorithm.HS512);
    try token.addIssuer("Allerate");
    try token.addSubject("Jwt");
    try token.addIssuedAt();
    try token.addExpiresAt(utils.getSecondsFromDays(1));
    try token.addPayload("name", .{ .string = "John Allerate" });
    try token.addPayload("admin", .{ .bool = true });
    try token.addPayload("slot", .{ .integer = 2 });

    var tokenBase64 = jwt.String.init(allocator);
    defer tokenBase64.deinit();
    _ = try j.encode(Algorithm.HS512, .{ .key = "veryS3cret:-)" }, &token, &tokenBase64);

    std.log.info("{s}", .{tokenBase64.str()});

    // try token.addExpiresAtValidator();

    // var array = std.ArrayList(Value).init(allocator);
    // try array.append(.{ .integer = 1 });
    // try array.append(.{ .integer = 2 });
    // try array.append(.{ .integer = 3 });

    // var v: Value = .{ .array = array };
    // var vo = jwt.ValidatorOp{ .in = v };
    // try token.addValidator("slot", vo);

    // var vo2 = jwt.ValidatorOp{ .storeValue = jwt.TokenClaim.init(allocator) };
    // defer vo2.storeValue.deinit();
    // try token.addValidator("name", vo2);

    // try token.decode(Algorithm.HS512, .{ .key = "veryS3cret:-)" }, encodedToken.str());

    //std.log.info("{s}", .{vo2.storeValue.string.str()});
}

test "all tests" {
    _ = @import("jwt.zig");
}

const std = @import("std");
const utils = @import("jwt/utils.zig");
const cert_utils = @import("jwt/cert_utils.zig");
const jwt = @import("jwt.zig").Jwt;
const Jwt = jwt.Jwt;
const validator = jwt.validator;
const Algorithm = jwt.Algorithm;
const Validator = jwt.Validator;
const Value = std.json.Value;

var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 12 }){};
const allocator = gpa.allocator();

pub fn main() !void {
    var certUtils = cert_utils.CertUtils.init(allocator);
    defer certUtils.deinit();

    try certUtils.loadCertificates();

    var j = Jwt.init(allocator);

    const alg = Algorithm.HS512;
    const issuer = "Allerate";

    var token = jwt.Token.init(allocator);
    defer token.deinit();

    try token.createDefaultHeader(alg);
    try token.addIssuer(issuer);
    try token.addSubject("Jwt");
    try token.addIssuedAt();
    try token.addExpiresAt(utils.getSecondsFromDays(1));
    try token.addPayload("name", .{ .string = "John Allerate" });
    try token.addPayload("admin", .{ .bool = true });
    try token.addPayload("slot", .{ .integer = 2 });

    var roles = std.ArrayList(Value).init(allocator);
    defer roles.deinit();

    try roles.append(.{ .string = "root" });
    try roles.appendSlice(&[_]Value{ .{ .string = "admin" }, .{ .string = "user" } });

    try token.addPayload("roles", .{ .array = roles });

    var tokenBase64 = try j.encode(alg, .{ .key = "veryS3cret:-)" }, &token);

    std.log.info("{s}", .{tokenBase64});

    var headerValidator = try validator.createDefaultHeaderValidator(allocator, alg.phrase());
    defer headerValidator.deinit();

    var payloadValidator = try validator.createDefaultPayloadValidator(allocator, issuer);

    var array = std.ArrayList(Value).init(allocator);
    try array.appendSlice(&[_]Value{.{ .integer = 1 }});
    try payloadValidator.addValidator("slot", .{ .in = .{ .array = array } });

    token.reset();
    try j.decode(alg, .{ .key = "veryS3cret:-)" }, .{
        .saveHeader = true,
        .savePayload = true,
        .headerValidator = headerValidator,
        .payloadValidator = payloadValidator,
    }, tokenBase64, &token);

    var keys = token.payload.keys();

    for (keys) |key| {
        if (token.payload.get(key)) |value| {
            std.log.info("Key: {s} value: {}", .{ key, value });
        }
    }
}

test "all tests" {
    _ = @import("jwt.zig");
}

const std = @import("std");
const Allocator = std.mem.Allocator;
const zjwt = @import("zjwt");
const utils = zjwt.utils;

const secretKey = "secret";
const issuer = "zjwt";

pub fn createToken(alg: zjwt.Algorithm, signatureOptions: zjwt.SignatureOptions, buffer: *std.ArrayList(u8), allocator: Allocator) !void {
    var j = zjwt.ZJwt.init(allocator);
    var token = zjwt.Token.init(allocator);
    defer token.deinit();

    try token.createDefaultHeader(alg);
    try token.addIssuer(issuer);
    try token.addSubject("username");
    try token.addIssuedAt();
    try token.addNotBefore(std.time.timestamp() - 1);
    try token.addExpiresAt(3600);
    try token.addAudience("public");
    var uuid: [36]u8 = undefined;
    try token.addJwtId(try utils.createUUID(&uuid));
    try token.addPayload("name", .{ .string = "John Allerate" });
    try token.addPayload("admin", .{ .bool = true });
    try token.addPayload("slot", .{ .integer = 2 });
    try token.addArray([]const u8, "roles", &[_][]const u8{ "admin", "user", "sales" });
    try token.addArray(i64, "slotes", &[_]i64{ 1, 2, 6, 9 });

    try buffer.appendSlice(try j.encode(alg, signatureOptions, &token));
}

pub fn vlidateToken(alg: zjwt.Algorithm, signatureOptions: zjwt.SignatureOptions, tokenBase64: []const u8, allocator: Allocator) !zjwt.Token {
    var j = zjwt.ZJwt.init(allocator);
    var token = zjwt.Token.init(allocator);

    var headerValidator = try zjwt.validator.createDefaultHeaderValidator(allocator, alg.phrase());
    defer headerValidator.deinit();

    var payloadValidator = try zjwt.validator.createDefaultPayloadValidator(allocator, issuer);
    try payloadValidator.addNotBeforeValidator();
    try j.decode(alg, signatureOptions, .{
        .saveHeader = true,
        .savePayload = true,
        .headerValidator = headerValidator, // Validate the header
        .payloadValidator = payloadValidator, // Validate the payload
    }, tokenBase64, &token);

    return token;
}

pub fn encodeAndDecode(allocator: Allocator) !void {
    const alg = zjwt.Algorithm.HS256;

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try createToken(alg, .{ .key = secretKey }, &buffer, allocator);
    std.debug.print("Token generated. You can validate it on https://jwt.io\n{s}\n", .{buffer.items});
    var token = try vlidateToken(alg, .{ .key = secretKey }, buffer.items, allocator);
    defer token.deinit();
}

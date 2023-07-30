const std = @import("std");
const Allocator = std.mem.Allocator;
const zjwt = @import("zjwt");
const examples = @import("examples.zig");

const secretKey = "veryS3cret:-)";
const issuer = "zjwt";

fn createToken(alg: zjwt.Algorithm, signatureOptions: zjwt.SignatureOptions, buffer: *std.ArrayList(u8), allocator: Allocator) !void {
    var j = zjwt.ZJwt.init(allocator);

    var token = zjwt.Token.init(allocator);
    defer token.deinit();

    // Builds the header as follows { "typ": "JWT", "alg": "HS256" }
    try token.createDefaultHeader(alg);

    // Builds the payload as follows { "iss": "zjwt", "sub": "username", "iat": 1690702984, "exp": 1690706584 }
    try token.addIssuer(issuer);
    try token.addSubject("username");
    try token.addIssuedAt();
    try token.addExpiresAt(3600);

    // Encodes the header and the token to base64 and creates the signature using the chosen algorithm
    try buffer.appendSlice(try j.encode(alg, signatureOptions, &token));
}

fn vlidateToken(alg: zjwt.Algorithm, signatureOptions: zjwt.SignatureOptions, tokenBase64: []const u8, allocator: Allocator) !void {
    var j = zjwt.ZJwt.init(allocator);
    var token = zjwt.Token.init(allocator);
    defer token.deinit();

    // The default header validator checks the algorithm and the type
    var headerValidator = try zjwt.validator.createDefaultHeaderValidator(allocator, alg.phrase());
    defer headerValidator.deinit();

    // The default payload validator checks the issuer and the expiration time
    var payloadValidator = try zjwt.validator.createDefaultPayloadValidator(allocator, issuer);

    try j.decode(alg, signatureOptions, .{
        .saveHeader = false, // Do not save the header
        .savePayload = true, // Save the payload
        .headerValidator = headerValidator, // Validate the header
        .payloadValidator = payloadValidator, // Validate the payload
    }, tokenBase64, &token);

    std.debug.print("Token validated for subject: {s}\n", .{token.payload.get(zjwt.Claims.SUBJECT).?.string});
}

fn createAndValidateToken(alg: zjwt.Algorithm, allocator: Allocator) !void {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try createToken(alg, .{ .key = secretKey }, &buffer, allocator);
    std.debug.print("Token generated. You can validate it on https://jwt.io\n{s}\n", .{buffer.items});
    try vlidateToken(alg, .{ .key = secretKey }, buffer.items, allocator);
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const alg = zjwt.Algorithm.HS256;
    try createAndValidateToken(alg, allocator);

    // More examples
    try examples.execExamples(allocator);
}

test "example test" {
    const allocator = std.testing.allocator;
    const alg = zjwt.Algorithm.HS256;
    try createAndValidateToken(alg, allocator);
    try examples.execExamples(allocator);
}

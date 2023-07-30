const std = @import("std");
const zjwt = @import("zjwt");

const utils = zjwt.utils;
const cert_utils = zjwt.cert_tils;
const key = zjwt.key;
const ZJwt = zjwt.ZJwt;
const validator = zjwt.validator;
const Algorithm = zjwt.Algorithm;
const Validator = zjwt.Validator;
const Value = std.json.Value;
const ecdsa = std.crypto.sign.ecdsa;

var gpa = std.heap.GeneralPurposeAllocator(.{ .stack_trace_frames = 12 }){};
const allocator = gpa.allocator();

const issuer = "Allerate";

fn createToken(alg: Algorithm, signatureOptions: zjwt.SignatureOptions, buffer: *std.ArrayList(u8)) !void {
    var j = ZJwt.init(allocator);

    var token = zjwt.Token.init(allocator);
    defer token.deinit();

    try token.createDefaultHeader(alg);
    try token.addIssuer(issuer);
    try token.addSubject("Jwt");
    try token.addIssuedAt();
    try token.addExpiresAt(utils.getSecondsFromDays(1));
    try token.addPayload("name", .{ .string = "John Allerate" });
    try token.addPayload("admin", .{ .bool = true });
    try token.addPayload("slot", .{ .integer = 2 });

    var roles = std.ArrayList(Value).init(token.arenaAllocator.allocator());
    defer roles.deinit();
    try roles.append(.{ .string = "root" });
    try roles.appendSlice(&[_]Value{ .{ .string = "admin" }, .{ .string = "user" } });
    try token.addPayload("roles", .{ .array = roles });

    try buffer.appendSlice(try j.encode(alg, signatureOptions, &token));
}

fn vlidateToken(alg: Algorithm, signatureOptions: zjwt.SignatureOptions, tokenBase64: []const u8) !void {
    var j = ZJwt.init(allocator);
    var token = zjwt.Token.init(allocator);
    defer token.deinit();

    var headerValidator = try validator.createDefaultHeaderValidator(allocator, alg.phrase());
    defer headerValidator.deinit();

    var payloadValidator = try validator.createDefaultPayloadValidator(allocator, issuer);

    var array = std.ArrayList(Value).init(allocator);
    defer array.deinit();
    try array.appendSlice(&[_]Value{ .{ .integer = 1 }, .{ .integer = 2 }, .{ .integer = 3 } });
    try payloadValidator.addValidator("slot", .{ .in = .{ .array = array } });

    try j.decode(alg, signatureOptions, .{
        .saveHeader = true,
        .savePayload = true,
        .headerValidator = headerValidator,
        .payloadValidator = payloadValidator,
    }, tokenBase64, &token);
}

fn hmacs(alg: zjwt.Algorithm) !void {
    const secretKey = "veryS3cret:-)";

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try createToken(alg, .{ .key = secretKey }, &buffer);
    std.log.info("{s}", .{buffer.items});
    try vlidateToken(alg, .{ .key = secretKey }, buffer.items);
}

pub fn ecdsaAlg(alg: zjwt.Algorithm) !void {
    var token = zjwt.Token.init(allocator);
    defer token.deinit();

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    const pkf = try key.ECPrivateKey.fromDer("certs/ecdsa_prime256v1_onlypk.der", allocator);

    try createToken(alg, .{ .key = pkf.privateKey }, &buffer);
    std.log.info("{s}", .{buffer.items});
    try vlidateToken(alg, .{ .key = pkf.privateKey }, buffer.items);
}

pub fn main() !void {
    // try hmacs(Algorithm.HS256);
    // try hmacs(Algorithm.HS384);
    // try hmacs(Algorithm.HS512);
    // try ecdsaAlg(Algorithm.ES256);
    try ecdsaAlg(Algorithm.ES256);
}

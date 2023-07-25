const std = @import("std");
const hmac = std.crypto.auth.hmac;
const json = std.json;
const mem = std.mem;

const claims = @import("claims.zig");
const headers = @import("headers.zig");
const str = @import("string.zig");

const Allocator = mem.Allocator;
const Claims = claims.Claims;
const Headers = headers.Headers;
const ObjectMap = json.ObjectMap;
const String = str.String;
const Value = json.Value;

const ALG = "alg";
const TYP = "typ";
const JWT = "JWT";
const KID = "kid";

pub const Algorithm = enum {
    const Self = @This();

    HS256,
    HS384,
    HS512,

    pub fn phrase(self: Algorithm) []const u8 {
        return switch (self) {
            else => @tagName(self),
        };
    }

    pub fn macLength(self: Self) usize {
        return switch (self) {
            .HS256 => hmac.sha2.HmacSha256.mac_length,
            .HS384 => hmac.sha2.HmacSha384.mac_length,
            .HS512 => hmac.sha2.HmacSha512.mac_length,
        };
    }
};

pub const Header = struct {
    alg: Algorithm,
    typ: []const u8,
    kid: ?[]const u8,
};

allocator: Allocator,
header: ObjectMap,
payload: ObjectMap,

pub const Token = @This();

pub fn init(allocator: Allocator) Token {
    return .{
        .allocator = allocator,
        .header = ObjectMap.init(allocator),
        .payload = ObjectMap.init(allocator),
    };
}

pub fn deinit(token: *Token) void {
    token.header.deinit();
    token.payload.deinit();
}

pub fn reset(token: *Token) void {
    token.header.clearRetainingCapacity();
    token.payload.clearRetainingCapacity();
}

// ++++++++
// Headers
// ++++++++
pub fn createDefaultHeader(token: *Token, alg: Algorithm) !void {
    try token.addType();
    try token.addAlgorithm(alg);
}

pub fn addHeader(token: *Token, key: []const u8, value: Value) !void {
    try token.header.put(key, value);
}

pub fn addType(token: *Token) !void {
    try token.addHeader(Headers.TYPE, .{ .string = Headers.TYPE_JWT });
}

pub fn addAlgorithm(token: *Token, alg: Algorithm) !void {
    try token.addHeader(Headers.ALGORITHM, .{ .string = alg.phrase() });
}

// ++++++++
// Payload
// ++++++++

pub fn addPayload(token: *Token, key: []const u8, value: Value) !void {
    try token.payload.put(key, value);
}

pub fn addIssuer(token: *Token, subject: []const u8) !void {
    try token.payload.put(Claims.ISSUER, .{ .string = subject });
}

pub fn addSubject(token: *Token, subject: []const u8) !void {
    try token.payload.put(Claims.SUBJECT, .{ .string = subject });
}

pub fn addAudience(token: *Token, subject: []const u8) !void {
    try token.payload.put(Claims.AUDIENCE, .{ .string = subject });
}

pub fn addExpiresAt(token: *Token, durationInSeconds: i64) !void {
    try token.payload.put(Claims.EXPIRES_AT, .{ .integer = getTimestamp(durationInSeconds) });
}

pub fn addNotBefore(token: *Token, durationInSeconds: i64) void {
    try token.payload.put(Claims.NOT_BEFORE, .{ .integer = getTimestamp(durationInSeconds) });
}

pub fn addIssuedAt(token: *Token) !void {
    try token.payload.put(Claims.ISSUED_AT, .{ .integer = getTimestamp(0) });
}

pub fn addJwtId(token: *Token, subject: []const u8) !void {
    try token.payload.put(Claims.JWT_ID, .{ .string = subject });
}

pub fn getTimestamp(deltaInSeconds: i64) i64 {
    return std.time.timestamp() + deltaInSeconds;
}

test "basiscs" {
    std.testing.refAllDecls(@This());
}

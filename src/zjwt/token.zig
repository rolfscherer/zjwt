const std = @import("std");
const hmac = std.crypto.auth.hmac;
const json = std.json;
const mem = std.mem;
const ecdsa = std.crypto.sign.ecdsa;

const claims = @import("claims.zig");
const headers = @import("headers.zig");

const Allocator = mem.Allocator;
const Claims = claims.Claims;
const Headers = headers.Headers;
const ObjectMap = json.ObjectMap;
const Array = json.Array;
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
    ES256,
    ES384,

    pub fn phrase(self: Algorithm) []const u8 {
        return switch (self) {
            else => @tagName(self),
        };
    }

    pub fn signatureLength(self: Self) usize {
        return switch (self) {
            .HS256 => hmac.sha2.HmacSha256.mac_length,
            .HS384 => hmac.sha2.HmacSha384.mac_length,
            .HS512 => hmac.sha2.HmacSha512.mac_length,
            .ES256 => ecdsa.EcdsaP256Sha256.Signature.encoded_length,
            .ES384 => ecdsa.EcdsaP384Sha384.Signature.encoded_length,
        };
    }
};

pub const Header = struct {
    alg: Algorithm,
    typ: []const u8,
    kid: ?[]const u8,
};

allocator: Allocator,
arenaAllocator: std.heap.ArenaAllocator,
header: ObjectMap,
payload: ObjectMap,
tokenBase64: std.ArrayList(u8),

pub const Token = @This();

pub fn init(allocator: Allocator) Token {
    return .{
        .allocator = allocator,
        .arenaAllocator = std.heap.ArenaAllocator.init(allocator),
        .header = ObjectMap.init(allocator),
        .payload = ObjectMap.init(allocator),
        .tokenBase64 = std.ArrayList(u8).init(allocator),
    };
}

pub fn deinit(token: *Token) void {
    token.header.deinit();
    token.payload.deinit();
    token.arenaAllocator.deinit();
    token.tokenBase64.deinit();
}

pub fn reset(token: *Token) void {
    token.header.clearRetainingCapacity();
    token.payload.clearRetainingCapacity();
    token.tokenBase64.clearRetainingCapacity();
    _ = token.arenaAllocator.reset(.retain_capacity);
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

pub fn cloneAndAddHeader(token: *Token, key: []const u8, value: Value) !void {
    try token.addHeader(try token.clone(key), try token.cloneValue(value));
}

// ++++++++
// Payload
// ++++++++

pub fn cloneAndAddPayload(token: *Token, key: []const u8, value: Value) !void {
    try token.addPayload(try token.clone(key), try token.cloneValue(value));
}

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

pub fn addNotBefore(token: *Token, durationInSeconds: i64) !void {
    try token.payload.put(Claims.NOT_BEFORE, .{ .integer = getTimestamp(durationInSeconds) });
}

pub fn addIssuedAt(token: *Token) !void {
    try token.payload.put(Claims.ISSUED_AT, .{ .integer = getTimestamp(0) });
}

pub fn addJwtId(token: *Token, subject: []const u8) !void {
    try token.payload.put(Claims.JWT_ID, .{ .string = subject });
}

// ++++++++
// Miscs
// ++++++++

fn cloneArray(token: *Token, source: *const Array) !Array {
    var dest = Array.init(token.arenaAllocator.allocator());

    for (source.items) |item| {
        const newItem = try token.cloneValue2(item);
        try dest.append(newItem);
    }

    return dest;
}

fn cloneValue(token: *Token, value: Value) !Value {
    switch (value) {
        .string => return .{ .string = try token.clone(value.string) },
        .number_string => return .{ .string = try token.clone(value.number_string) },
        .array => {
            var dest = Array.init(token.arenaAllocator.allocator());
            for (value.array.items) |item| {
                const newItem = try token.cloneValue(item);
                try dest.append(newItem);
            }
            return .{ .array = dest };
        },
        .object => return .{ .object = try value.object.cloneWithAllocator(token.arenaAllocator.allocator()) },
        else => return value,
    }
}

fn clone(token: *Token, source: []const u8) ![]const u8 {
    var dest = try token.arenaAllocator.allocator().alloc(u8, source.len);
    mem.copy(u8, dest, source);

    return dest;
}

pub fn getTimestamp(deltaInSeconds: i64) i64 {
    return std.time.timestamp() + deltaInSeconds;
}

test "basics" {
    std.testing.refAllDecls(@This());
}

const std = @import("std");
pub const token = @import("jwt/token.zig");
pub const validator = @import("jwt/validator.zig");
pub const Claims = @import("jwt/claims.zig").Claims;
pub const Headers = @import("jwt/headers.zig").Headers;
const mem = std.mem;
const json = std.json;
const hmac = std.crypto.auth.hmac;
const ecdsa = std.crypto.sign.ecdsa;
const base64url = std.base64.url_safe_no_pad;

pub const Algorithm = token.Algorithm;
const Allocator = mem.Allocator;
const ObjectMap = json.ObjectMap;
pub const Token = token.Token;
pub const Validator = validator.Validator;
pub const ValidatorItems = validator.ValidatorItems;
const Value = json.Value;

pub const Jwt = @This();

allocator: Allocator,

const DELIMITER = ".";

pub const Error = error{
    InvalidJsonFormat,
    InvalidSignature,
    WrongNumbersOfParts,
};

pub const SignatureOptions = struct {
    key: []const u8,
};

pub const DecodeOptions = struct {
    saveHeader: bool = false,
    savePayload: bool = false,
    headerValidator: ?Validator = null,
    payloadValidator: ?Validator = null,
};

pub fn init(allocator: Allocator) Jwt {
    return .{
        .allocator = allocator,
    };
}

pub fn encode(jwt: *Jwt, alg: Algorithm, signatureOptions: SignatureOptions, tokenToEncode: *Token) ![]const u8 {
    var bufferJson = std.ArrayList(u8).init(jwt.allocator);
    defer bufferJson.deinit();

    //
    // JWT-Header
    //

    // encode header (base 64)
    try std.json.stringify(Value{ .object = tokenToEncode.header }, .{}, bufferJson.writer());
    var len = base64url.Encoder.calcSize(bufferJson.items.len);
    var headerBase64 = try jwt.allocator.alloc(u8, len);
    defer jwt.allocator.free(headerBase64);
    try tokenToEncode.tokenBase64.appendSlice(base64url.Encoder.encode(headerBase64, bufferJson.items));
    try tokenToEncode.tokenBase64.appendSlice(DELIMITER);

    //
    // JWT-Payload
    //

    // encode payload (base 64)
    bufferJson.clearRetainingCapacity();
    try std.json.stringify(Value{ .object = tokenToEncode.payload }, .{}, bufferJson.writer());
    len = base64url.Encoder.calcSize(bufferJson.items.len);
    var payloadBase64 = try jwt.allocator.alloc(u8, len);
    defer jwt.allocator.free(payloadBase64);
    try tokenToEncode.tokenBase64.appendSlice(base64url.Encoder.encode(payloadBase64, bufferJson.items));

    //
    // JWT-Signature
    //

    // calc and encode signature (base 64)
    var signature = try jwt.allocator.alloc(u8, alg.signatureLength());
    defer jwt.allocator.free(signature);
    try generateSignature(alg, signatureOptions.key, tokenToEncode.tokenBase64.items, signature);
    len = base64url.Encoder.calcSize(signature.len);
    var signatureBase64 = try jwt.allocator.alloc(u8, len);
    defer jwt.allocator.free(signatureBase64);
    try tokenToEncode.tokenBase64.appendSlice(DELIMITER);
    try tokenToEncode.tokenBase64.appendSlice(base64url.Encoder.encode(signatureBase64, signature));

    return tokenToEncode.tokenBase64.items;
}

pub fn generateSignature(alg: Algorithm, key: []const u8, tokenBase64: []const u8, buffer: []u8) !void {
    switch (alg) {
        .HS256 => try generateHmacSignature(hmac.sha2.HmacSha256, key, tokenBase64, buffer),
        .HS384 => try generateHmacSignature(hmac.sha2.HmacSha384, key, tokenBase64, buffer),
        .HS512 => try generateHmacSignature(hmac.sha2.HmacSha512, key, tokenBase64, buffer),
        .ES256 => try generateEcdsSignature(ecdsa.EcdsaP256Sha256, key, tokenBase64, buffer),
        .ES384 => try generateEcdsSignature(ecdsa.EcdsaP384Sha384, key, tokenBase64, buffer),
    }
}

fn getSecretKey(ecdsFn: anytype, key: []const u8) !ecdsFn.SecretKey {
    var keyBuffer: [ecdsFn.SecretKey.encoded_length]u8 = undefined;
    mem.copy(u8, keyBuffer[0..ecdsFn.SecretKey.encoded_length], key);
    return try ecdsFn.SecretKey.fromBytes(keyBuffer);
}

fn generateEcdsSignature(ecdsFn: anytype, key: []const u8, tokenBase64: []const u8, buffer: []u8) !void {
    const secretKey = try getSecretKey(ecdsFn, key);
    var noise: [ecdsFn.noise_length]u8 = undefined;
    std.crypto.random.bytes(&noise);
    const kp = try ecdsFn.KeyPair.fromSecretKey(secretKey);
    const sig = try kp.sign(tokenBase64, noise);

    mem.copy(u8, buffer[0..ecdsFn.Signature.encoded_length], &sig.toBytes());
}

fn generateHmacSignature(hmacFn: anytype, key: []const u8, tokenBase64: []const u8, buffer: []u8) !void {
    var h = hmacFn.init(key);
    h.update(tokenBase64);
    var out: [hmacFn.mac_length]u8 = undefined;
    h.final(&out);
    mem.copy(u8, buffer[0..hmacFn.mac_length], &out);
}

pub fn decode(jwt: *Jwt, alg: Algorithm, signatureOptions: SignatureOptions, decodeOptions: DecodeOptions, tokenBase64: []const u8, decodedToken: *Token) !void {
    var it = mem.splitSequence(u8, tokenBase64, DELIMITER);

    var jwtToken = std.ArrayList(u8).init(jwt.allocator);
    defer jwtToken.deinit();

    // Header
    var item = it.next();
    if (item) |headerBase64| {
        if (decodeOptions.saveHeader or decodeOptions.headerValidator != null) {
            try jwt.decodeHeader(headerBase64, decodedToken, decodeOptions);
        }
        try jwtToken.appendSlice(headerBase64);
        try jwtToken.appendSlice(DELIMITER);
    } else {
        return error.WrongNumbersOfParts;
    }

    // Payload
    item = it.next();
    if (item) |payloadBase64| {
        if (decodeOptions.savePayload or decodeOptions.payloadValidator != null) {
            try jwt.decodePayload(payloadBase64, decodedToken, decodeOptions);
        }
        try jwtToken.appendSlice(payloadBase64);
    } else {
        return error.WrongNumbersOfParts;
    }

    // Signature
    item = it.next();
    if (item) |signatureBase64| {
        try jwt.parseAndValidateSignature(alg, signatureOptions, signatureBase64, jwtToken.items);
    } else {
        return error.WrongNumbersOfParts;
    }
}

fn decodeHeader(jwt: *Jwt, headerBase64: []const u8, decodedToken: *Token, decodeOptions: DecodeOptions) !void {
    var headerJson = try jwt.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(headerBase64));
    defer jwt.allocator.free(headerJson);
    try base64url.Decoder.decode(headerJson, headerBase64);
    var parsed = json.parseFromSlice(Value, jwt.allocator, headerJson, .{}) catch return error.InvalidJwtFormat;
    defer parsed.deinit();
    var headerObject = parsed.value.object;

    if (decodeOptions.saveHeader) {
        for (headerObject.keys()) |key| {
            const item = headerObject.get(key);
            if (item) |value| {
                try decodedToken.cloneAndAddHeader(key, value);
            }
        }
    }

    if (decodeOptions.headerValidator) |*headerValidator| {
        try headerValidator.validate(headerObject);
    }
}

fn decodePayload(jwt: *Jwt, payloadBase64: []const u8, decodedToken: *Token, decodeOptions: DecodeOptions) !void {
    var payloadJson = try jwt.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(payloadBase64));
    defer jwt.allocator.free(payloadJson);
    try base64url.Decoder.decode(payloadJson, payloadBase64);

    var parsed = json.parseFromSlice(Value, jwt.allocator, payloadJson, .{}) catch return error.InvalidJsonFormat;
    defer parsed.deinit();

    var payloadObject = parsed.value.object;
    for (payloadObject.keys()) |key| {
        const item = payloadObject.get(key);

        if (item) |value| {
            if (decodeOptions.savePayload) {
                try decodedToken.cloneAndAddPayload(key, value);
            }
        }
    }
}

fn parseAndValidateSignature(jwt: *Jwt, alg: Algorithm, signatureOptions: SignatureOptions, signatureBase64: []const u8, tokenBase64: []const u8) !void {
    var signatureToken = try jwt.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(signatureBase64));
    defer jwt.allocator.free(signatureToken);
    try base64url.Decoder.decode(signatureToken, signatureBase64);

    switch (alg) {
        .HS256, .HS384, .HS512 => {
            var signatureCalculated = try jwt.allocator.alloc(u8, alg.signatureLength());
            defer jwt.allocator.free(signatureCalculated);
            try generateSignature(alg, signatureOptions.key, tokenBase64, signatureCalculated);
            if (!mem.eql(u8, signatureToken, signatureCalculated)) return error.InvalidSignature;
        },
        .ES256 => {
            try validateEcdsSignature(ecdsa.EcdsaP256Sha256, signatureOptions.key, tokenBase64, signatureToken);
        },
        else => {},
    }
}

fn validateEcdsSignature(ecdsFn: anytype, key: []const u8, tokenBase64: []const u8, signatureToken: []const u8) !void {
    const secretKey = try getSecretKey(ecdsFn, key);
    const kp = try ecdsFn.KeyPair.fromSecretKey(secretKey);

    var sigBuffer: [ecdsFn.Signature.encoded_length]u8 = undefined;
    mem.copy(u8, sigBuffer[0..ecdsFn.Signature.encoded_length], signatureToken);

    const sig = ecdsFn.Signature.fromBytes(sigBuffer);
    try sig.verify(tokenBase64, kp.public_key);
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("jwt/claims.zig");
    _ = @import("jwt/headers.zig");
    _ = @import("jwt/token.zig");
    _ = @import("jwt/utils.zig");
    _ = @import("jwt/validator.zig");
    _ = @import("jwt/cert_utils.zig");
    _ = @import("jwt/key.zig");
    _ = @import("jwt/asn1.zig");
}

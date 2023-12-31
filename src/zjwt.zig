const std = @import("std");

pub const Claims = @import("zjwt/claims.zig").Claims;
pub const Headers = @import("zjwt/headers.zig").Headers;
pub const token = @import("zjwt/token.zig");
pub const validator = @import("zjwt/validator.zig");
pub const utils = @import("zjwt/utils.zig");
pub const key = @import("zjwt/key.zig");
pub const cert_utils = @import("zjwt/cert_utils.zig");

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

pub const ZJwt = @This();

allocator: Allocator,

const DELIMITER = ".";

pub const Error = error{
    /// Invalid JSON format
    InvalidJsonFormat,
    /// Invalid signature
    InvalidSignature,
    // Wrong numbers of JWT parts
    WrongNumbersOfParts,
};

pub const SignatureOptions = struct {
    /// A secret (HS) , a secret key (EC) or a private key (RSA)
    key: []const u8,
    publicKey: ?[]const u8 = null,
};

/// Options used when decoding
pub const DecodeOptions = struct {
    /// If true, the header attributes are stored in the token and can be evaluated or used further
    saveHeader: bool = false,
    /// If true, the payload attributes (reserved, public or private claims) are stored in the token and can be evaluated or used further
    savePayload: bool = false,

    /// Configurable header validator, which can check the attributes individually.
    headerValidator: ?Validator = null,

    /// Configurable payload validator, which can check the attributes individually.
    payloadValidator: ?Validator = null,
};

pub fn init(allocator: Allocator) ZJwt {
    return .{
        .allocator = allocator,
    };
}

/// Encodes the token based on the values of the token with the ObjectMaps header and payload and calculates the signature using the algorithm.
pub fn encode(jwt: *ZJwt, alg: Algorithm, signatureOptions: SignatureOptions, tokenToEncode: *Token) ![]const u8 {
    var bufferJson = std.ArrayList(u8).init(jwt.allocator);
    defer bufferJson.deinit();

    //
    // JWT-Header
    //

    // encode header (base 64)
    try std.json.stringify(Value{ .object = tokenToEncode.header }, .{}, bufferJson.writer());
    var base64Header = try utils.base64UrlEncoder(bufferJson.items, jwt.allocator);
    defer base64Header.deinit();
    try tokenToEncode.tokenBase64.appendSlice(base64Header.items);
    try tokenToEncode.tokenBase64.appendSlice(DELIMITER);

    //
    // JWT-Payload
    //

    // encode payload (base 64)
    bufferJson.clearRetainingCapacity();
    try std.json.stringify(Value{ .object = tokenToEncode.payload }, .{}, bufferJson.writer());
    var base64Payload = try utils.base64UrlEncoder(bufferJson.items, jwt.allocator);
    defer base64Payload.deinit();
    try tokenToEncode.tokenBase64.appendSlice(base64Payload.items);

    //
    // JWT-Signature
    //

    // calc and encode signature (base 64)
    var signature = try jwt.allocator.alloc(u8, alg.signatureLength());
    defer jwt.allocator.free(signature);
    try generateSignature(alg, signatureOptions.key, tokenToEncode.tokenBase64.items, signature);

    var base64Signature = try utils.base64UrlEncoder(signature, jwt.allocator);
    defer base64Signature.deinit();
    try tokenToEncode.tokenBase64.appendSlice(DELIMITER);
    try tokenToEncode.tokenBase64.appendSlice(base64Signature.items);

    return tokenToEncode.tokenBase64.items;
}

/// Use the enum to select the signature function
pub fn generateSignature(alg: Algorithm, secretKey: []const u8, tokenBase64: []const u8, buffer: []u8) !void {
    switch (alg) {
        .HS256 => try generateHmacSignature(hmac.sha2.HmacSha256, secretKey, tokenBase64, buffer),
        .HS384 => try generateHmacSignature(hmac.sha2.HmacSha384, secretKey, tokenBase64, buffer),
        .HS512 => try generateHmacSignature(hmac.sha2.HmacSha512, secretKey, tokenBase64, buffer),
        .ES256 => try generateEcdsSignature(ecdsa.EcdsaP256Sha256, secretKey, tokenBase64, buffer),
        .ES384 => try generateEcdsSignature(ecdsa.EcdsaP384Sha384, secretKey, tokenBase64, buffer),
    }
}

fn getSecretKey(ecdsFn: anytype, secretKey: []const u8) !ecdsFn.SecretKey {
    var keyBuffer: [ecdsFn.SecretKey.encoded_length]u8 = undefined;
    mem.copy(u8, keyBuffer[0..ecdsFn.SecretKey.encoded_length], secretKey);
    return try ecdsFn.SecretKey.fromBytes(keyBuffer);
}

fn generateEcdsSignature(ecdsFn: anytype, secretKey: []const u8, tokenBase64: []const u8, buffer: []u8) !void {
    const secretKeyInt = try getSecretKey(ecdsFn, secretKey);
    var noise: [ecdsFn.noise_length]u8 = undefined;
    std.crypto.random.bytes(&noise);
    const kp = try ecdsFn.KeyPair.fromSecretKey(secretKeyInt);
    const sig = try kp.sign(tokenBase64, noise);

    mem.copy(u8, buffer[0..ecdsFn.Signature.encoded_length], &sig.toBytes());
}

fn generateHmacSignature(hmacFn: anytype, secretKey: []const u8, tokenBase64: []const u8, buffer: []u8) !void {
    var h = hmacFn.init(secretKey);
    h.update(tokenBase64);
    var out: [hmacFn.mac_length]u8 = undefined;
    h.final(&out);
    mem.copy(u8, buffer[0..hmacFn.mac_length], &out);
}

/// Decodes the token and verifies the signature. Further checks are carried out using the DecodeOptions.
pub fn decode(jwt: *ZJwt, alg: Algorithm, signatureOptions: SignatureOptions, decodeOptions: DecodeOptions, tokenBase64: []const u8, decodedToken: *Token) !void {
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

/// Decodes the header
fn decodeHeader(jwt: *ZJwt, headerBase64: []const u8, decodedToken: *Token, decodeOptions: DecodeOptions) !void {
    var headerJson = try utils.base64UrlDecoder(headerBase64, jwt.allocator);
    defer headerJson.deinit();

    var parsed = json.parseFromSlice(Value, jwt.allocator, headerJson.items, .{}) catch return error.InvalidJwtFormat;
    defer parsed.deinit();
    var headerObject = parsed.value.object;

    // Checks whether the data should be stored in the token
    if (decodeOptions.saveHeader) {
        for (headerObject.keys()) |headerKey| {
            const item = headerObject.get(headerKey);
            if (item) |value| {
                try decodedToken.cloneAndAddHeader(headerKey, value);
            }
        }
    }

    // If there is a header validator, it will be executed
    if (decodeOptions.headerValidator) |*headerValidator| {
        try headerValidator.validate(headerObject);
    }
}

fn decodePayload(jwt: *ZJwt, payloadBase64: []const u8, decodedToken: *Token, decodeOptions: DecodeOptions) !void {
    var payloadJson = try utils.base64UrlDecoder(payloadBase64, jwt.allocator);
    defer payloadJson.deinit();

    var parsed = json.parseFromSlice(Value, jwt.allocator, payloadJson.items, .{}) catch return error.InvalidJsonFormat;
    defer parsed.deinit();

    var payloadObject = parsed.value.object;
    for (payloadObject.keys()) |payloadKey| {
        const item = payloadObject.get(payloadKey);

        if (item) |value| {
            if (decodeOptions.savePayload) {
                try decodedToken.cloneAndAddPayload(payloadKey, value);
            }
        }
    }

    // If there is a payload validator, it will be executed
    if (decodeOptions.payloadValidator) |*payloadValidator| {
        try payloadValidator.validate(payloadObject);
    }
}

fn parseAndValidateSignature(jwt: *ZJwt, alg: Algorithm, signatureOptions: SignatureOptions, signatureBase64: []const u8, tokenBase64: []const u8) !void {
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
            try validateEcdsaSignature(ecdsa.EcdsaP256Sha256, signatureOptions, tokenBase64, signatureToken);
        },
        .ES384 => {
            try validateEcdsaSignature(ecdsa.EcdsaP384Sha384, signatureOptions, tokenBase64, signatureToken);
        },
    }
}

fn validateEcdsaSignature(ecdsFn: anytype, signatureOptions: SignatureOptions, tokenBase64: []const u8, signatureToken: []const u8) !void {
    var sigBuffer: [ecdsFn.Signature.encoded_length]u8 = undefined;
    mem.copy(u8, sigBuffer[0..ecdsFn.Signature.encoded_length], signatureToken);
    const sig = ecdsFn.Signature.fromBytes(sigBuffer);

    if (signatureOptions.publicKey) |publicKey| {
        const pk = try ecdsFn.PublicKey.fromSec1(publicKey);
        try sig.verify(tokenBase64, pk);
    } else {
        const secretKeyInt = try getSecretKey(ecdsFn, signatureOptions.key);
        const kp = try ecdsFn.KeyPair.fromSecretKey(secretKeyInt);
        try sig.verify(tokenBase64, kp.public_key);
    }
}

test {
    std.testing.refAllDecls(@This());
    _ = @import("zjwt/claims.zig");
    _ = @import("zjwt/headers.zig");
    _ = @import("zjwt/token.zig");
    _ = @import("zjwt/utils.zig");
    _ = @import("zjwt/validator.zig");
    _ = @import("zjwt/cert_utils.zig");
    _ = @import("zjwt/key.zig");
    _ = @import("zjwt/asn1.zig");
}

test "ok encode and decode" {
    var allocator = std.testing.allocator;

    const alg = Algorithm.ES384;
    var j = ZJwt.init(allocator);

    var t = Token.init(allocator);
    defer t.deinit();
    try t.createDefaultHeader(alg);
    try t.addIssuer("zjwt");
    try t.addSubject("adri@adri.com");
    try t.addIssuedAt();
    try t.addExpiresAt(3600);

    var tokenBase64 = std.ArrayList(u8).init(allocator);
    defer tokenBase64.deinit();

    try tokenBase64.appendSlice(try j.encode(alg, .{ .key = "secret" }, &t));
    t.reset();

    try j.decode(alg, .{ .key = "secret" }, .{
        .saveHeader = true,
        .savePayload = true,
    }, tokenBase64.items, &t);

    try std.testing.expect(mem.eql(u8, "adri@adri.com", t.getSubject().?));
}

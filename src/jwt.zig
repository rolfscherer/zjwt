const std = @import("std");
const str = @import("string.zig");
const Claims = @import("claims.zig").Claims;
const mem = std.mem;
const json = std.json;
const hmac = std.crypto.auth.hmac;
const base64url = std.base64.url_safe_no_pad;

const Allocator = mem.Allocator;
const String = str.String;
const Value = json.Value;
const ObjectMap = json.ObjectMap;
const ValidatorItems = std.ArrayList(ValidatorItem);

pub const Jwt = @This();

allocator: Allocator,
jwtString: String,
payload: ObjectMap,
validatorItems: ValidatorItems,

const ALG = "alg";
const TYP = "typ";
const JWT = "JWT";
const KID = "kid";
const DELIMITER = ".";

pub const Error = error{
    OutOfMemory,
    WrongNumbersOfParts,
    InvalidJwtFormat,
    InvalidAlgorithm,
    InvalidSignatture,
    ValidatorError,
};

pub const Header = struct {
    alg: Algorithm,
    typ: []const u8,
};

const Range = struct {
    from: i64,
    to: i64,
};

const ValidatorOp = union(enum) {

    // zig fmt: off
    exists, 
    notExists, 
    timestampInRange: Range, 
    timestampGtNow, 
    timestampGt: i64, 
    timestampLt: i64, 
    eq: Value,
    notEq: Value,
    in: Value,
    storeValue,
    // zig fmt: on
};

const ValidatorItem = struct {
    key: []const u8,
    validatorOp: ValidatorOp,
};

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

pub const SignatureOptions = struct {
    key: []const u8,
    kid: ?[]const u8 = null,
};

pub fn init(allocator: Allocator) Jwt {
    return .{
        .allocator = allocator,
        .jwtString = String.init(allocator),
        .payload = ObjectMap.init(allocator),
        .validatorItems = ValidatorItems.init(allocator),
    };
}

pub fn deinit(jwt: *Jwt) void {
    jwt.jwtString.deinit();
    jwt.payload.deinit();
    jwt.validatorItems.deinit();
}

pub fn addPayload(jwt: *Jwt, key: []const u8, value: Value) !void {
    try jwt.payload.put(key, value);
}

pub fn addIssuer(jwt: *Jwt, subject: []const u8) !void {
    try jwt.payload.put(Claims.ISSUER, .{ .string = subject });
}

pub fn addSubject(jwt: *Jwt, subject: []const u8) !void {
    try jwt.payload.put(Claims.SUBJECT, .{ .string = subject });
}

pub fn addAudience(jwt: *Jwt, subject: []const u8) !void {
    try jwt.payload.put(Claims.AUDIENCE, .{ .string = subject });
}

pub fn addExpiresAt(jwt: *Jwt, durationInSeconds: i64) !void {
    try jwt.payload.put(Claims.EXPIRES_AT, .{ .integer = getTimestamp(durationInSeconds) });
}

pub fn addNotBefore(jwt: *Jwt, durationInSeconds: i64) void {
    try jwt.payload.put(Claims.NOT_BEFORE, .{ .integer = getTimestamp(durationInSeconds) });
}

pub fn addIssuedAt(jwt: *Jwt) !void {
    try jwt.payload.put(Claims.ISSUED_AT, .{ .integer = getTimestamp(0) });
}

pub fn addJwtId(jwt: *Jwt, subject: []const u8) !void {
    try jwt.payload.put(Claims.JWT_ID, .{ .string = subject });
}

pub fn getTimestamp(deltaInSeconds: i64) i64 {
    return std.time.timestamp() + deltaInSeconds;
}

// pub fn getTimestamp(jwt: *Jwt, deltaInSeconds: i64) !String {
//     const time = std.time.timestamp() + deltaInSeconds;
//     var buffer: [10]u8 = undefined;
//     var fbs = std.io.fixedBufferStream(&buffer);
//     try std.fmt.formatIntValue(time, "", .{}, fbs.writer());
//     return try String.init_with_str(jwt.allocator, &buffer);
// }

pub fn addValidator(jwt: *Jwt, key: []const u8, validatorOp: ValidatorOp) !void {
    try jwt.validatorItems.append(.{
        .key = key,
        .validatorOp = validatorOp,
    });
}

pub fn addExpiresAtValidator(jwt: *Jwt) !void {
    try jwt.validatorItems.append(.{
        .key = Claims.EXPIRES_AT,
        .validatorOp = .timestampGtNow,
    });
}

pub fn encode(jwt: *Jwt, alg: Algorithm, signatureOptions: SignatureOptions) !*String {

    //
    // JWT-Header
    //
    var header = ObjectMap.init(jwt.allocator);
    defer header.deinit();

    try header.put(ALG, .{ .string = alg.phrase() });
    try header.put(TYP, .{ .string = JWT });
    if (signatureOptions.kid) |kid| {
        try header.put(KID, .{ .string = kid });
    }

    var bufferJson = std.ArrayList(u8).init(jwt.allocator);
    defer bufferJson.deinit();

    // encode header (base 64)
    try std.json.stringify(Value{ .object = header }, .{}, bufferJson.writer());
    var len = base64url.Encoder.calcSize(bufferJson.items.len);
    var headerBase64 = try jwt.allocator.alloc(u8, len);
    defer jwt.allocator.free(headerBase64);
    jwt.jwtString.clear();
    try jwt.jwtString.concat(base64url.Encoder.encode(headerBase64, bufferJson.items));
    try jwt.jwtString.concat(DELIMITER);

    //
    // JWT-Payload
    //

    // encode payload (base 64)
    bufferJson.clearRetainingCapacity();
    try std.json.stringify(Value{ .object = jwt.payload }, .{}, bufferJson.writer());
    len = base64url.Encoder.calcSize(bufferJson.items.len);
    var payloadBase64 = try jwt.allocator.alloc(u8, len);
    defer jwt.allocator.free(payloadBase64);
    try jwt.jwtString.concat(base64url.Encoder.encode(payloadBase64, bufferJson.items));

    //
    // JWT-Signature
    //

    // calc and encode signature (base 64)
    var signature = try jwt.allocator.alloc(u8, alg.macLength());
    defer jwt.allocator.free(signature);
    try generateSignature(alg, signatureOptions.key, jwt.jwtString.str(), signature);
    len = base64url.Encoder.calcSize(signature.len);
    var signatureBase64 = try jwt.allocator.alloc(u8, len);
    defer jwt.allocator.free(signatureBase64);
    try jwt.jwtString.concat(DELIMITER);
    try jwt.jwtString.concat(base64url.Encoder.encode(signatureBase64, signature));

    return &jwt.jwtString;
}

pub fn decode(jwt: *Jwt, alg: Algorithm, signatureOptions: SignatureOptions, token: []const u8) !void {
    var it = mem.splitSequence(u8, token, ".");

    var jwtToken = String.init(jwt.allocator);

    // Header
    var item = it.next();
    if (item) |headerBase64| {
        try jwt.parseAndValidateHeader(alg, headerBase64);
        try jwtToken.concat(headerBase64);
        try jwtToken.concat(DELIMITER);
    } else {
        return error.WrongNumbersOfParts;
    }

    // Payload
    item = it.next();
    if (item) |payloadBase64| {
        try jwt.parseAndValidatePayload(payloadBase64);
        try jwtToken.concat(payloadBase64);
    } else {
        return error.WrongNumbersOfParts;
    }

    // Signature
    item = it.next();
    if (item) |signatureBase64| {
        try jwt.parseAndValidateSignature(alg, signatureOptions, signatureBase64, jwtToken.str());
    } else {
        return error.WrongNumbersOfParts;
    }
}

fn parseAndValidateHeader(jwt: *Jwt, alg: Algorithm, headerBase64: []const u8) !void {
    var headerJson = try jwt.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(headerBase64));
    defer jwt.allocator.free(headerJson);
    try base64url.Decoder.decode(headerJson, headerBase64);
    var parser = json.parseFromSlice(Header, jwt.allocator, headerJson, .{}) catch return error.InvalidJwtFormat;
    defer parser.deinit();
    var header: Header = parser.value;

    if (!mem.eql(u8, JWT, header.typ)) return error.InvalidJwtFormat;
    if (alg != header.alg) return error.InvalidAlgorithm;
}

fn parseAndValidatePayload(jwt: *Jwt, payloadBase64: []const u8) !void {
    var payloadJson = try jwt.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(payloadBase64));
    defer jwt.allocator.free(payloadJson);
    try base64url.Decoder.decode(payloadJson, payloadBase64);

    var parsed = json.parseFromSlice(Value, jwt.allocator, payloadJson, .{}) catch return error.InvalidJwtFormat;
    defer parsed.deinit();

    if (jwt.validatorItems.items.len == 0) {
        return;
    }

    var object = parsed.value.object;

    for (jwt.validatorItems.items) |item| {
        const entry = object.get(item.key);

        if (entry) |value| {
            switch (item.validatorOp) {
                .exists => {},
                .notExists => return error.ValidatorError,
                .timestampInRange => |range| {
                    if (value.integer > range.to) return error.ValidatorError;
                    if (value.integer < range.from) return error.ValidatorError;
                },
                .timestampGtNow => if (value.integer <= std.time.timestamp()) return error.ValidatorError,
                .timestampGt => |ts| if (value.integer <= ts) return error.ValidatorError,
                .timestampLt => |ts| if (value.integer >= ts) return error.ValidatorError,
                .eq => |val| {
                    switch (val) {
                        .bool => if (val.bool != value.bool) return error.ValidatorError,
                        .integer => if (val.integer != value.integer) return error.ValidatorError,
                        .float => if (val.float != value.float) return error.ValidatorError,
                        .string => if (!mem.eql(u8, val.string, value.string)) return error.ValidatorError,
                        else => {},
                    }
                },
                .notEq => |val| {
                    switch (val) {
                        .bool => if (val.bool == value.bool) return error.ValidatorError,
                        .integer => if (val.integer == value.integer) return error.ValidatorError,
                        .float => if (val.float == value.float) return error.ValidatorError,
                        .string => if (mem.eql(u8, val.string, value.string)) return error.ValidatorError,
                        else => {},
                    }
                },
                .in => {},
                .storeValue => {},
            }
        } else {
            switch (item.validatorOp) {
                .notExists => {},
                else => return error.ValidatorError,
            }
        }
    }

    // var it = root.object.iterator();

    // while (it.next()) |pair| {

    //     std.log.info("{any}", .{@TypeOf(pair.value_ptr.*)});
    //     std.log.info("{any}", .{pair.value_ptr.*});
    //     std.log.info("{s}", .{pair.key_ptr.*});
    // }
}

fn parseAndValidateSignature(jwt: *Jwt, alg: Algorithm, signatureOptions: SignatureOptions, signatureBase64: []const u8, token: []const u8) !void {
    var signatureToken = try jwt.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(signatureBase64));
    defer jwt.allocator.free(signatureToken);
    try base64url.Decoder.decode(signatureToken, signatureBase64);

    var signatureCalculated = try jwt.allocator.alloc(u8, alg.macLength());
    defer jwt.allocator.free(signatureCalculated);
    try generateSignature(alg, signatureOptions.key, token, signatureCalculated);

    if (!mem.eql(u8, signatureToken, signatureCalculated)) return error.InvalidSignatture;
}

pub fn generateSignature(alg: Algorithm, key: []const u8, token: []const u8, buffer: []u8) !void {
    switch (alg) {
        .HS256 => try generateHmac(hmac.sha2.HmacSha256, key, token, buffer),
        .HS384 => try generateHmac(hmac.sha2.HmacSha384, key, token, buffer),
        .HS512 => try generateHmac(hmac.sha2.HmacSha512, key, token, buffer),
    }
}

fn generateHmac(hmacFn: anytype, key: []const u8, token: []const u8, buffer: []u8) !void {
    var h = hmacFn.init(key);
    h.update(token);
    var out: [hmacFn.mac_length]u8 = undefined;
    h.final(&out);
    mem.copy(u8, buffer[0..hmacFn.mac_length], &out);
}

test {
    std.testing.refAllDecls(@This());
}

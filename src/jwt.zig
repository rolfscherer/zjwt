const std = @import("std");
const str = @import("jwt/string.zig");
const token = @import("jwt/token.zig");
const Claims = @import("jwt/claims.zig").Claims;
const mem = std.mem;
const json = std.json;
const hmac = std.crypto.auth.hmac;
const base64url = std.base64.url_safe_no_pad;

pub const Algorithm = token.Algorithm;
const Allocator = mem.Allocator;
pub const String = str.String;
// const ObjectMap = json.ObjectMap;
pub const Token = token.Token;
//const ValidatorItems = std.ArrayList(ValidatorItem);
const Value = json.Value;

pub const Jwt = @This();

allocator: Allocator,

//validatorItems: ValidatorItems,

const DELIMITER = ".";

// pub const Error = error{
//     OutOfMemory,
//     WrongNumbersOfParts,
//     InvalidJwtFormat,
//     InvalidAlgorithm,
//     InvalidSignatture,
//     ValidatorError,
// };

pub const SignatureOptions = struct {
    key: []const u8,
};

pub fn init(allocator: Allocator) Jwt {
    return .{
        .allocator = allocator,
    };
}

pub fn encode(jwt: *Jwt, alg: Algorithm, signatureOptions: SignatureOptions, tokenToEncode: *Token, tokenBase64: *String) !*String {
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
    try tokenBase64.concat(base64url.Encoder.encode(headerBase64, bufferJson.items));
    try tokenBase64.concat(DELIMITER);

    //
    // JWT-Payload
    //

    // encode payload (base 64)
    bufferJson.clearRetainingCapacity();
    try std.json.stringify(Value{ .object = tokenToEncode.payload }, .{}, bufferJson.writer());
    len = base64url.Encoder.calcSize(bufferJson.items.len);
    var payloadBase64 = try jwt.allocator.alloc(u8, len);
    defer jwt.allocator.free(payloadBase64);
    try tokenBase64.concat(base64url.Encoder.encode(payloadBase64, bufferJson.items));

    //
    // JWT-Signature
    //

    // calc and encode signature (base 64)
    var signature = try jwt.allocator.alloc(u8, alg.macLength());
    defer jwt.allocator.free(signature);
    try generateSignature(alg, signatureOptions.key, tokenBase64.str(), signature);
    len = base64url.Encoder.calcSize(signature.len);
    var signatureBase64 = try jwt.allocator.alloc(u8, len);
    defer jwt.allocator.free(signatureBase64);
    try tokenBase64.concat(DELIMITER);
    try tokenBase64.concat(base64url.Encoder.encode(signatureBase64, signature));

    return tokenBase64;
}

pub fn generateSignature(alg: Algorithm, key: []const u8, tokenBase64: []const u8, buffer: []u8) !void {
    switch (alg) {
        .HS256 => try generateHmac(hmac.sha2.HmacSha256, key, tokenBase64, buffer),
        .HS384 => try generateHmac(hmac.sha2.HmacSha384, key, tokenBase64, buffer),
        .HS512 => try generateHmac(hmac.sha2.HmacSha512, key, tokenBase64, buffer),
    }
}

fn generateHmac(hmacFn: anytype, key: []const u8, tokenBase64: []const u8, buffer: []u8) !void {
    var h = hmacFn.init(key);
    h.update(tokenBase64);
    var out: [hmacFn.mac_length]u8 = undefined;
    h.final(&out);
    mem.copy(u8, buffer[0..hmacFn.mac_length], &out);
}

// pub fn decode(jwt: *Jwt, alg: Algorithm, signatureOptions: SignatureOptions, tokenBase64: []const u8) !void {
//     var it = mem.splitSequence(u8, tokenBase64, ".");

//     var jwtToken = String.init(jwt.allocator);

//     // Header
//     var item = it.next();
//     if (item) |headerBase64| {
//         try jwt.parseAndValidateHeader(alg, headerBase64);
//         try jwtToken.concat(headerBase64);
//         try jwtToken.concat(DELIMITER);
//     } else {
//         return error.WrongNumbersOfParts;
//     }

//     // Payload
//     item = it.next();
//     if (item) |payloadBase64| {
//         try jwt.parseAndValidatePayload(payloadBase64);
//         try jwtToken.concat(payloadBase64);
//     } else {
//         return error.WrongNumbersOfParts;
//     }

//     // Signature
//     item = it.next();
//     if (item) |signatureBase64| {
//         try jwt.parseAndValidateSignature(alg, signatureOptions, signatureBase64, jwtToken.str());
//     } else {
//         return error.WrongNumbersOfParts;
//     }
// }

// fn parseAndValidateHeader(jwt: *Jwt, alg: Algorithm, headerBase64: []const u8) !void {
//     var headerJson = try jwt.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(headerBase64));
//     defer jwt.allocator.free(headerJson);
//     try base64url.Decoder.decode(headerJson, headerBase64);
//     var parser = json.parseFromSlice(Header, jwt.allocator, headerJson, .{ .ignore_unknown_fields = true }) catch return error.InvalidJwtFormat;
//     defer parser.deinit();
//     var header: Header = parser.value;

//     if (!mem.eql(u8, JWT, header.typ)) return error.InvalidJwtFormat;
//     if (alg != header.alg) return error.InvalidAlgorithm;
// }

// fn parseAndValidatePayload(jwt: *Jwt, payloadBase64: []const u8) !void {
//     var payloadJson = try jwt.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(payloadBase64));
//     defer jwt.allocator.free(payloadJson);
//     try base64url.Decoder.decode(payloadJson, payloadBase64);

//     var parsed = json.parseFromSlice(Value, jwt.allocator, payloadJson, .{}) catch return error.InvalidJwtFormat;
//     defer parsed.deinit();

//     if (jwt.validatorItems.items.len == 0) {
//         return;
//     }

//     var payloadObject = parsed.value.object;

//     for (jwt.validatorItems.items) |*validatorItem| {
//         var payloadEntry = payloadObject.get(validatorItem.key);

//         if (payloadEntry) |payloadValue| {
//             switch (validatorItem.validatorOp) {
//                 .exists => {},
//                 .notExists => return error.ValidatorError,
//                 .timestampInRange => |range| {
//                     if (payloadValue.integer > range.to) return error.ValidatorError;
//                     if (payloadValue.integer < range.from) return error.ValidatorError;
//                 },
//                 .timestampGtNow => if (payloadValue.integer <= std.time.timestamp()) return error.ValidatorError,
//                 .timestampGt => |ts| if (payloadValue.integer <= ts) return error.ValidatorError,
//                 .timestampLt => |ts| if (payloadValue.integer >= ts) return error.ValidatorError,
//                 .eq => |val| {
//                     switch (val) {
//                         .bool => if (val.bool != payloadValue.bool) return error.ValidatorError,
//                         .integer => if (val.integer != payloadValue.integer) return error.ValidatorError,
//                         .float => if (val.float != payloadValue.float) return error.ValidatorError,
//                         .string => if (!mem.eql(u8, val.string, payloadValue.string)) return error.ValidatorError,
//                         else => {},
//                     }
//                 },
//                 .notEq => |val| {
//                     switch (val) {
//                         .bool => if (val.bool == payloadValue.bool) return error.ValidatorError,
//                         .integer => if (val.integer == payloadValue.integer) return error.ValidatorError,
//                         .float => if (val.float == payloadValue.float) return error.ValidatorError,
//                         .string => if (mem.eql(u8, val.string, payloadValue.string)) return error.ValidatorError,
//                         else => {},
//                     }
//                 },
//                 .in => |val| {
//                     switch (payloadValue) {
//                         .integer => {
//                             for (val.array.items) |ai| {
//                                 if (ai.integer == payloadValue.integer) break;
//                             } else return error.ValidatorError;
//                         },
//                         .float => {
//                             for (val.array.items) |ai| {
//                                 if (ai.float == payloadValue.float) break;
//                             } else return error.ValidatorError;
//                         },
//                         .string => {
//                             for (val.array.items) |ai| {
//                                 if (mem.eql(u8, ai.string, payloadValue.string)) break;
//                             } else return error.ValidatorError;
//                         },
//                         else => {},
//                     }
//                 },
//                 .storeValue => |*val| {
//                     switch (payloadValue) {
//                         .bool => val.*.value = .{ .bool = payloadValue.bool },
//                         .integer => val.*.value = .{ .integer = payloadValue.integer },
//                         .float => val.*.value = .{ .float = payloadValue.float },
//                         .string => {
//                             try val.*.string.concat(payloadValue.string);
//                             std.log.info("{s}", .{val.*.string.str()});
//                         },
//                         else => {},
//                     }
//                 },
//             }
//         } else {
//             switch (validatorItem.validatorOp) {
//                 .notExists => {},
//                 else => return error.ValidatorError,
//             }
//         }
//     }
// }

// fn parseAndValidateSignature(jwt: *Jwt, alg: Algorithm, signatureOptions: SignatureOptions, signatureBase64: []const u8, tokenBase64: []const u8) !void {
//     var signatureToken = try jwt.allocator.alloc(u8, try base64url.Decoder.calcSizeForSlice(signatureBase64));
//     defer jwt.allocator.free(signatureToken);
//     try base64url.Decoder.decode(signatureToken, signatureBase64);

//     var signatureCalculated = try jwt.allocator.alloc(u8, alg.macLength());
//     defer jwt.allocator.free(signatureCalculated);
//     try generateSignature(alg, signatureOptions.key, tokenBase64, signatureCalculated);

//     if (!mem.eql(u8, signatureToken, signatureCalculated)) return error.InvalidSignatture;
// }

test {
    std.testing.refAllDecls(@This());
    _ = @import("jwt/claims.zig");
    _ = @import("jwt/headers.zig");
    _ = @import("jwt/string.zig");
    _ = @import("jwt/token.zig");
    _ = @import("jwt/utils.zig");
    _ = @import("jwt/validator.zig");
}

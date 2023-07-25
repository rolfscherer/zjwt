const std = @import("std");
const json = std.json;

const Value = json.Value;

pub const Range = struct {
    from: i64,
    to: i64,
};

pub const ValidatorOp = union(enum) {

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
    // zig fmt: on
};

pub const ValidatorItem = struct {
    key: []const u8,
    validatorOp: ValidatorOp,
};

// pub fn addValidator(jwt: *Jwt, key: []const u8, validatorOp: ValidatorOp) !void {
//     try jwt.validatorItems.append(.{
//         .key = key,
//         .validatorOp = validatorOp,
//     });
// }

// pub fn addExpiresAtValidator(jwt: *Jwt) !void {
//     try jwt.validatorItems.append(.{
//         .key = Claims.EXPIRES_AT,
//         .validatorOp = .timestampGtNow,
//     });
// }

test "basiscs" {
    std.testing.refAllDecls(@This());
}

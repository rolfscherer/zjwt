const std = @import("std");
const mem = std.mem;
const json = std.json;

const Allocator = mem.Allocator;
pub const ValidatorItems = std.ArrayList(ValidatorItem);
const Claims = @import("claims.zig").Claims;
const Headers = @import("headers.zig").Headers;

const ObjectMap = json.ObjectMap;
const Value = json.Value;

pub const Error = error{
    InvalidJwtFormat,
    InvalidType,
    InvalidAlgorithm,
    ValidatorError,
    TypeNotSupported,
};

allocator: Allocator,
validatorItems: ValidatorItems,

pub const Validator = @This();

pub fn createDefaultHeaderValidator(allocator: Allocator, algorithm: []const u8) !Validator {
    var validator = Validator.init(allocator);

    try validator.addValidator(Headers.TYPE, .{ .eq = .{ .string = Headers.TYPE_JWT } });
    try validator.addValidator(Headers.ALGORITHM, .{ .eq = .{ .string = algorithm } });

    return validator;
}

pub fn init(allocator: Allocator) Validator {
    return .{
        .allocator = allocator,
        .validatorItems = ValidatorItems.init(allocator),
    };
}

pub fn deinit(validator: *Validator) void {
    validator.validatorItems.deinit();
}

pub const Range = struct {
    from: i64,
    to: i64,
};

pub const ValidatorOp = union(enum) {

    // zig fmt: off
    exists,
    notExists,
    timestampInRange: Range,
    timestampNotInRange: Range,
    timestampGtNow,
    timestampGt: i64,
    timestampLt: i64,
    eq: Value,
    notEq: Value,
    in: Value,
    notIn: Value,
    // zig fmt: on
};

pub const ValidatorItem = struct {
    key: []const u8,
    validatorOp: ValidatorOp,
};

pub fn addValidator(validator: *Validator, key: []const u8, validatorOp: ValidatorOp) !void {
    try validator.validatorItems.append(.{
        .key = key,
        .validatorOp = validatorOp,
    });
}

pub fn addExpiresAtValidator(validator: *Validator) !void {
    try validator.validatorItems.append(.{
        .key = Claims.EXPIRES_AT,
        .validatorOp = .timestampGtNow,
    });
}

pub fn validate(objectMap: ObjectMap, validatorItems: ValidatorItems) !void {
    for (validatorItems.items) |val| {
        const item = objectMap.get(val.key);
        if (item) |v| {
            switch (val.validatorOp) {
                .exists => {},
                .notExists => return error.ValidatorError,
                .timestampInRange => |range| if (v.integer > range.to or v.integer < range.from) return error.ValidatorError,
                .timestampNotInRange => |range| if (v.integer < range.to or v.integer > range.from) return error.ValidatorError,
                .timestampGtNow => if (v.integer <= std.time.timestamp()) return error.ValidatorError,
                .timestampGt => |ts| if (v.integer <= ts) return error.ValidatorError,
                .timestampLt => |ts| if (v.integer >= ts) return error.ValidatorError,
                .eq => |inner| if (!try eq(inner, v)) return error.ValidatorError,
                .notEq => |inner| if (try eq(inner, v)) return error.ValidatorError,
                .in => |inner| if (!try in(inner, v)) return error.ValidatorError,
                .notIn => |inner| if (try in(inner, v)) return error.ValidatorError,
            }
        } else {
            switch (val.validatorOp) {
                .notExists => {},
                else => return error.ValidatorError,
            }
        }
    }
}

fn eq(a: Value, b: Value) !bool {
    switch (a) {
        .bool => return a.bool == b.bool,
        .integer => return a.integer == b.integer,
        .float => return a.float == b.float,
        .string => return mem.eql(u8, a.string, b.string),
        .number_string => return mem.eql(u8, a.string, b.string),
        else => return error.TypeNotSupported,
    }
}

fn in(a: Value, b: Value) !bool {
    switch (b) {
        .integer => {
            for (a.array.items) |ai| {
                if (ai.integer == b.integer) return true;
            } else return false;
        },
        .float => {
            for (a.array.items) |ai| {
                if (ai.float == b.float) return true;
            } else return false;
        },
        .string => {
            for (a.array.items) |ai| {
                if (mem.eql(u8, ai.string, b.string)) return true;
            } else return false;
        },
        .number_string => {
            for (a.array.items) |ai| {
                if (mem.eql(u8, ai.number_string, b.number_string)) return true;
            } else return error.ValidatorError;
        },
        else => return error.TypeNotSupported,
    }
}

test "basiscs" {
    std.testing.refAllDecls(@This());
}

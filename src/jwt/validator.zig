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
    ValidationError,
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

pub fn validate(validator: *const Validator, objectMap: ObjectMap) !void {
    for (validator.validatorItems.items) |val| {
        const item = objectMap.get(val.key);
        if (item) |v| {
            switch (val.validatorOp) {
                .exists => {},
                .notExists => return error.ValidationError,
                .timestampInRange => |range| if (v.integer > range.to or v.integer < range.from) return error.ValidationError,
                .timestampNotInRange => |range| if (v.integer < range.to or v.integer > range.from) return error.ValidationError,
                .timestampGtNow => if (v.integer <= std.time.timestamp()) return error.ValidationError,
                .timestampGt => |ts| if (v.integer <= ts) return error.ValidationError,
                .timestampLt => |ts| if (v.integer >= ts) return error.ValidationError,
                .eq => |inner| if (!try eq(inner, v)) return error.ValidationError,
                .notEq => |inner| if (try eq(inner, v)) return error.ValidationError,
                .in => |inner| if (!try in(inner, v)) return error.ValidationError,
                .notIn => |inner| if (try in(inner, v)) return error.ValidationError,
            }
        } else {
            switch (val.validatorOp) {
                .notExists => {},
                else => return error.ValidationError,
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
            } else return error.ValidationError;
        },
        else => return error.TypeNotSupported,
    }
}

test "basiscs" {
    std.testing.refAllDecls(@This());
}

test "expectError default zig testheader validator " {
    var validator = try createDefaultHeaderValidator(std.testing.allocator, "HS256");
    defer validator.deinit();

    var objectMap = ObjectMap.init(std.testing.allocator);
    defer objectMap.deinit();

    try std.testing.expectError(error.ValidationError, validator.validate(objectMap));
}

test "expect no error. header validator " {
    var alg = "HS256";
    var validator = try createDefaultHeaderValidator(std.testing.allocator, alg);
    defer validator.deinit();

    var objectMap = ObjectMap.init(std.testing.allocator);
    defer objectMap.deinit();

    try objectMap.put(Headers.TYPE, .{ .string = Headers.TYPE_JWT });
    try objectMap.put(Headers.ALGORITHM, .{ .string = alg });

    try std.testing.expectEqual({}, validator.validate(objectMap));
}

test "eq noteq Tests" {
    var vis = ValidatorItems.init(std.testing.allocator);
    defer vis.deinit();

    try vis.append(.{ .key = "bool", .validatorOp = .{ .eq = .{ .bool = true } } });
    try vis.append(.{ .key = "integer", .validatorOp = .{ .eq = .{ .integer = 1 } } });
    try vis.append(.{ .key = "float", .validatorOp = .{ .eq = .{ .float = 1.1 } } });
    try vis.append(.{ .key = "string", .validatorOp = .{ .eq = .{ .string = "positive" } } });
    try vis.append(.{ .key = "number_string", .validatorOp = .{ .eq = .{ .string = "-320.789" } } });

    var objectMap = ObjectMap.init(std.testing.allocator);
    defer objectMap.deinit();

    for (vis.items) |vi| {
        var validator = Validator.init(std.testing.allocator);
        defer validator.deinit();
        try validator.validatorItems.append(vi);

        // positive test
        try objectMap.put("bool", .{ .bool = true });
        try objectMap.put("integer", .{ .integer = 1 });
        try objectMap.put("float", .{ .float = 1.1 });
        try objectMap.put("string", .{ .string = "positive" });
        try objectMap.put("number_string", .{ .string = "-320.789" });
        try std.testing.expectEqual({}, validator.validate(objectMap));

        // negativ test
        objectMap.clearRetainingCapacity();
        try objectMap.put("bool", .{ .bool = false });
        try objectMap.put("integer", .{ .integer = 2 });
        try objectMap.put("float", .{ .float = 1.2 });
        try objectMap.put("string", .{ .string = "negative" });
        try objectMap.put("number_string", .{ .string = "+320.789" });
        try std.testing.expectError(error.ValidationError, validator.validate(objectMap));
    }
}

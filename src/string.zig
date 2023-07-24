const std = @import("std");
const mem = std.mem;

const Allocator = mem.Allocator;

pub const String = struct {
    allocator: Allocator,
    buffer: ?[]u8,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .buffer = null,
        };
    }

    pub fn init_with_str(allocator: Allocator, string: []const u8) !Self {
        var self = init(allocator);
        try self.concat(string);
        return self;
    }

    pub fn deinit(self: *Self) void {
        if (self.buffer) |buffer| self.allocator.free(buffer);
    }

    pub fn clear(self: *Self) void {
        self.deinit();
        self.buffer = null;
    }

    pub fn allocate(self: *Self, bytes: usize) !void {
        if (self.buffer) |buffer| {
            self.buffer = try self.allocator.realloc(buffer, bytes);
        } else {
            self.buffer = try self.allocator.alloc(u8, bytes);
        }
    }

    pub fn concat(self: *Self, string: []const u8) !void {
        if (self.buffer) |buffer| {
            try self.allocate(buffer.len + string.len);
            if (self.buffer) |buf| {
                mem.copy(u8, buf[buffer.len..], string[0..]);
            }
        } else {
            try self.allocate(string.len);
            if (self.buffer) |buffer| {
                mem.copy(u8, buffer[0..], string);
            }
        }
    }

    pub fn str(self: *Self) []const u8 {
        if (self.buffer) |buffer| return buffer;
        return "";
    }

    pub fn len(self: *Self) usize {
        if (self.buffer) |buffer| return buffer.len;
        return 0;
    }

    pub fn equel(self: *Self, string: []const u8) bool {
        if (self.buffer) |buffer| {
            return std.mem.eql(u8, buffer[0..], string);
        }
        return false;
    }
};

const assert = std.debug.assert;

test "test" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    const allocator = arena.allocator();

    defer arena.deinit();

    var str1 = String.init(allocator);
    var str2 = try String.init_with_str(allocator, "J");
    var str3 = try String.init_with_str(allocator, "W");
    var str4 = try String.init_with_str(allocator, "T");
    var str5 = try String.init_with_str(allocator, "JWT");
    var str6 = try String.init_with_str(allocator, "JSON Web Token");

    try str1.concat(str2.str());
    try str1.concat(str3.str());
    try str1.concat(str4.str());

    assert(str1.equel("JWT"));
    assert(str1.equel(str5.str()));
    assert(str1.len() == 3);

    try str5.concat(" -> ");
    try str5.concat(str6.str());

    const str = "JWT -> JSON Web Token";

    assert(str5.equel(str));
    assert(str5.len() == str.len);
}

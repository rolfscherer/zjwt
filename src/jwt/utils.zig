const std = @import("std");
const io = std.io;
const mem = std.mem;

pub const Error = error{
    MissingBeginMarker,
    MissingEndMarker,
};

pub fn getSecondsFromMinutes(num: i64) i64 {
    return num * 60;
}

pub fn getSecondsFromHours(num: i64) i64 {
    return num * 60 * 60;
}

pub fn getSecondsFromDays(num: i64) i64 {
    return num * 60 * 60 * 24;
}

pub fn base64Encode(source: []const u8, allocator: mem.Allocator) !std.ArrayList(u8) {
    const base64 = std.base64.standard.Encoder;

    const len = base64.calcSize(source.len);
    var buffer = try allocator.alloc(u8, len);
    _ = base64.encode(buffer, source);
    return std.ArrayList(u8).fromOwnedSlice(allocator, buffer);
}

pub fn base64Decode(source: []const u8, allocator: mem.Allocator) !std.ArrayList(u8) {
    const base64 = std.base64.standard.Decoder;

    const len = try base64.calcSizeForSlice(source);
    var buffer = try allocator.alloc(u8, len);
    _ = try base64.decode(buffer, source);
    return std.ArrayList(u8).fromOwnedSlice(allocator, buffer);
}

pub fn readFileRelative(subPath: []const u8, allocator: mem.Allocator) !std.ArrayList(u8) {
    const file = try std.fs.cwd().openFile(subPath, .{});
    defer file.close();

    const fb = try file.readToEndAlloc(allocator, 1024 * 1024);
    return std.ArrayList(u8).fromOwnedSlice(allocator, fb);
}

pub fn writeFileRelative(subPath: []const u8, source: []const u8) !void {
    var file = try std.fs.cwd().createFile(subPath, .{});
    defer file.close();
    try file.writeAll(source);
}

pub fn deleteFileRelative(subPath: []const u8) !void {
    _ = try std.fs.cwd().deleteFile(subPath);
}

pub fn writeFileRelativeWithMarkers(subPath: []const u8, source: []const u8, beginMarker: []const u8, endMarker: []const u8) !void {
    var file = try std.fs.cwd().createFile(subPath, .{});
    defer file.close();
    try file.writeAll(beginMarker);
    try file.writeAll("\n");
    try file.writeAll(source);
    try file.writeAll("\n");
    try file.writeAll(endMarker);
    try file.writeAll("\n");
}

pub fn readFileRelativeWithoutMarkers(subPath: []const u8, allocator: mem.Allocator, beginMarker: []const u8, endMarker: []const u8) !std.ArrayList(u8) {
    const array = try readFileRelative(subPath, allocator);
    defer array.deinit();

    if (mem.indexOfPos(u8, array.items, 0, beginMarker)) |beginMarkerStart| {
        const contentStart = beginMarkerStart + beginMarker.len;
        const contentEnd = mem.indexOfPos(u8, array.items, contentStart, endMarker) orelse
            return error.MissingEndMarker;
        const content = mem.trim(u8, array.items[contentStart..contentEnd], " \t\r\n");
        var newArray = std.ArrayList(u8).init(allocator);
        try newArray.appendSlice(content);
        return newArray;
    } else {
        return error.MissingBeginMarker;
    }
}

pub fn derToBase64(subPathSource: []const u8, subPathDest: []const u8, allocator: mem.Allocator, beginMarker: []const u8, endMarker: []const u8) !void {
    var source = try readFileRelative(subPathSource, allocator);
    defer source.deinit();

    const base64 = try base64Encode(source.items, allocator);
    defer base64.deinit();

    try writeFileRelativeWithMarkers(subPathDest, base64.items, beginMarker, endMarker);
}

test "basics" {
    std.testing.refAllDecls(@This());
}

test "base 64 tests" {
    const text = "Hello world!";

    const encoded = try base64Encode(text, std.testing.allocator);
    defer encoded.deinit();
    const decoded = try base64Decode(encoded.items, std.testing.allocator);
    defer decoded.deinit();

    try std.testing.expectEqual(true, mem.eql(u8, text, decoded.items));
}

test "file tests" {
    const fileName = "test.dat";
    const text = "That is a file, I hope";
    try writeFileRelative(fileName, text);
    const arrayList = try readFileRelative(fileName, std.testing.allocator);
    defer arrayList.deinit();
    try std.testing.expectEqual(true, mem.eql(u8, text, arrayList.items));
    try std.testing.expectEqual({}, deleteFileRelative(fileName));
}

test "file tests with markesr" {
    const fileName = "test.dat";
    const text = "That is a file, I hope";
    const beginMarker = "---test-start---";
    const endMarker = "---test-end---";

    try writeFileRelativeWithMarkers(fileName, text, beginMarker, endMarker);
    const arrayList = try readFileRelativeWithoutMarkers(fileName, std.testing.allocator, beginMarker, endMarker);
    defer arrayList.deinit();
    try std.testing.expectEqual(true, mem.eql(u8, text, arrayList.items));
    try std.testing.expectEqual({}, deleteFileRelative(fileName));
}

test "der to base64" {
    try derToBase64("certs/ecdsa_prime256v1_onlypk.der", "certs/ecdsa_prime256v1_pk_der.pem", std.testing.allocator, "-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----");
}

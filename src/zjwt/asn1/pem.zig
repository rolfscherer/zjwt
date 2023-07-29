const std = @import("std");
const mem = std.mem;

// RFC7468
const PEM_PREFIX_BEGIN = "-----BEGIN ";
const PEM_PREFIX_END = "-----END ";
const PEM_SUFFIX = "-----";

const Error = error{
    InvalidPEMFormat,
    MissingBeginMarker,
    MissingEndMarker,
};

pub fn isPEMFormatted(content: []const u8) bool {
    const pos = mem.indexOfPos(u8, content, 0, PEM_PREFIX_BEGIN);
    if (pos != null) {
        return true;
    }

    return false;
}

pub fn getPEMLabel(content: []const u8, allocator: mem.Allocator) !std.ArrayList(u8) {
    var label = std.ArrayList(u8).init(allocator);

    const pos = mem.indexOfPos(u8, content, 0, PEM_PREFIX_BEGIN);
    if (pos) |startIndex| {
        var idx = startIndex + PEM_PREFIX_BEGIN.len;

        while (idx < content.len) : (idx += 1) {
            if (content[idx] == '-' or content[idx] == '\r' or content[idx] == '\n') {
                break;
            }
            try label.append(content[idx]);
        }
    } else {
        return error.InvalidPEMFormat;
    }

    return label;
}

pub fn removePEMMarkers(content: []const u8, allocator: mem.Allocator) !std.ArrayList(u8) {
    const label = try getPEMLabel(content, allocator);
    defer label.deinit();

    var beginMarker = std.ArrayList(u8).init(allocator);
    var endMarker = std.ArrayList(u8).init(allocator);
    defer beginMarker.deinit();
    defer endMarker.deinit();

    try beginMarker.appendSlice(PEM_PREFIX_BEGIN);
    try beginMarker.appendSlice(label.items);
    try beginMarker.appendSlice(PEM_SUFFIX);

    try endMarker.appendSlice(PEM_PREFIX_END);
    try endMarker.appendSlice(label.items);
    try endMarker.appendSlice(PEM_SUFFIX);

    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    if (mem.indexOfPos(u8, content, 0, beginMarker.items)) |beginMarkerStart| {
        const contentStart = beginMarkerStart + beginMarker.items.len;
        const contentEnd = mem.indexOfPos(u8, content, contentStart, endMarker.items) orelse
            return error.MissingEndMarker;

        const b64 = mem.trim(u8, content[contentStart..contentEnd], " \t\r\n");
        try result.appendSlice(b64);
        return result;
    } else {
        return error.MissingBeginMarker;
    }
}

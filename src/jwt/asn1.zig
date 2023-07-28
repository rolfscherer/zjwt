const std = @import("std");
const io = std.io;
const mem = std.mem;

pub const Stream = io.FixedBufferStream([]u8);

pub const Error = error{
    FieldLengthToLarge,
    InvalidArgument,
    InvalidFormat,
    InvalidTagType,
    NotAllBytesDecoded,
};

pub const Tag = enum(u8) {
    BOOLEAN = 0x01,
    INTEGER = 0x02,
    BIT_STRING = 0x03,
    OCTET_STRING = 0x04,
    NULL = 0x05,
    OBJECT_IDENTIFIER = 0x06,
    UTCTime = 0x17,
    GeneralizedTime = 0x18,
    SEQUENCE = 0x30, // SEQUENCE OF
    SET = 0x31, // SET OF
};

pub const Decoder = struct {
    pub fn decodeLength(reader: anytype) !u64 {
        const len = try reader.readByte();

        // Short form
        if (len & 0x80 == 0) {
            return len;
        }

        // Long form
        const len_size = len & 0x7F;

        // length field larger than u64 is ignored
        if (len_size > 8) {
            return error.FieldLengthToLarge;
        }

        var i: usize = 0;
        var res: u64 = 0;
        while (i < len_size) : (i += 1) {
            res = (res << 8) | (try reader.readByte());
        }

        return res;
    }

    pub fn getLengthSize(len: u64) usize {
        if (len < 0x80) {
            return 1;
        }

        var res: usize = 1;
        var cur = len;
        while (cur > 0) {
            cur = cur >> 8;
            res += 1;
        }

        return res;
    }

    pub fn decodeOID(out: []u8, id: []const u8) usize {
        var start_idx: usize = 0;
        var cur_idx: usize = 0;
        var out_idx: usize = 0;
        while (start_idx < id.len) {
            if (start_idx == 0) {
                out[out_idx] = (id[0] / 40) + '0';
                out_idx += 1;
                out[out_idx] = '.';
                out_idx += 1;
                out[out_idx] = (id[0] % 40) + '0';
                out_idx += 1;
                start_idx += 1;
            } else {
                cur_idx = start_idx;
                while (id[cur_idx] > 0x80) {
                    cur_idx += 1;
                }
                cur_idx += 1;

                const code = decodeOIDInt(id[start_idx..cur_idx]);
                start_idx = cur_idx;

                const s = std.fmt.bufPrintIntToSlice(out[out_idx..], code, 10, .lower, .{});
                out_idx += s.len;
            }

            if (start_idx != id.len) {
                out[out_idx] = '.';
                out_idx += 1;
            }
        }

        return out_idx;
    }

    fn decodeOIDInt(bytes: []const u8) usize {
        var res: usize = 0;
        for (bytes, 0..) |b, i| {
            res *= 128;
            if (i == bytes.len - 1) {
                res += b;
            } else {
                res += (b - 0x80);
            }
        }

        return res;
    }

    pub fn decodeSequence(reader: anytype, allocator: mem.Allocator, comptime DecodeType: type) !DecodeType {
        const t = @as(Tag, @enumFromInt(try reader.readByte()));
        if (t != .SEQUENCE) {
            return error.InvalidType;
        }
        const len = try decodeLength(reader);
        var content = try allocator.alloc(u8, len);
        defer allocator.free(content);

        // read all content
        try reader.readNoEof(content);

        var stream = io.fixedBufferStream(content);
        const res = try DecodeType.decodeContent(&stream, allocator);
        errdefer res.deinit();

        if ((try stream.getPos()) != (try stream.getEndPos())) {
            return error.NotAllBytesDecoded;
        }

        return res;
    }

    pub fn decodeInteger(reader: anytype, allocator: mem.Allocator) ![]u8 {
        const t = @as(Tag, @enumFromInt(try reader.readByte()));
        if (t != .INTEGER) {
            return error.InvalidTagType;
        }
        const len = try decodeLength(reader);
        var content = try allocator.alloc(u8, len);
        errdefer allocator.free(content);

        // read all content
        try reader.readNoEof(content);

        return content;
    }

    pub fn decodeOctetString(reader: anytype, allocator: mem.Allocator) ![]u8 {
        const t = @as(Tag, @enumFromInt(try reader.readByte()));
        if (t != .OCTET_STRING) {
            return error.InvalidTagType;
        }
        const len = try decodeLength(reader);
        var content = try allocator.alloc(u8, len);
        errdefer allocator.free(content);

        // read all content
        try reader.readNoEof(content);

        return content;
    }
};

pub const ObjectIdentifier = struct {
    id: []u8,
    allocator: mem.Allocator,

    const Self = @This();

    pub fn deinit(self: Self) void {
        self.allocator.free(self.id);
    }

    pub fn decode(reader: anytype, allocator: mem.Allocator) !Self {
        const t = @as(Tag, @enumFromInt(try reader.readByte()));
        if (t != .OBJECT_IDENTIFIER) {
            return error.InvalidTagType;
        }
        const len = try Decoder.decodeLength(reader);
        var id_bin = try allocator.alloc(u8, len);
        defer allocator.free(id_bin);

        try reader.readNoEof(id_bin);

        // TODO: calculate buffer size
        var id_tmp: [100]u8 = undefined;
        const id_len = Decoder.decodeOID(&id_tmp, id_bin);
        var id = try allocator.alloc(u8, id_len);
        errdefer allocator.free(id);
        mem.copy(u8, id, id_tmp[0..id_len]);

        return Self{
            .id = id,
            .allocator = allocator,
        };
    }

    pub fn eql(a: Self, b: Self) bool {
        return mem.eql(u8, a.id, b.id);
    }
};

pub const Encoder = struct {
    pub fn encodeLength(len: u64, writer: anytype) !usize {
        if (len < 0x80) {
            try writer.writeByte(@as(u8, @intCast(len)));
            return 1;
        }

        var tmp = len;
        var end_idx: usize = 0;
        var res: [8]u8 = undefined;
        while (tmp > 0) {
            if (end_idx >= res.len) {
                return error.InvalidArgument;
            }

            res[end_idx] = @as(u8, @intCast(tmp & 0xFF));
            tmp = tmp >> 8;
            end_idx += 1;
        }

        const len_len = end_idx + 1;
        try writer.writeByte(@as(u8, @intCast((end_idx & 0x7F) | 0x80)));
        while (end_idx > 0) {
            end_idx -= 1;
            try writer.writeByte(res[end_idx]);
        }

        return len_len;
    }

    // https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
    fn encodeOID(out: []u8, id: []const u8) !usize {
        var count: usize = 0;
        var out_idx: usize = 0;
        var start_idx: usize = 0;
        for (id, 0..) |c, i| {
            if (i != (id.len - 1) and c != '.') {
                continue;
            }
            var end_idx = i;
            if (i == (id.len - 1)) {
                end_idx = id.len;
            }

            const code = try std.fmt.parseInt(usize, id[start_idx..end_idx], 10);
            if (count == 0) {
                out[out_idx] = @as(u8, @intCast(code));
                count += 1;
            } else if (count == 1) {
                out[out_idx] = @as(u8, @intCast(out[out_idx] * 40 + code));
                out_idx += 1;
                count += 1;
            } else {
                out_idx += encodeOIDInt(out[out_idx..], code);
            }
            start_idx = i + 1;
        }

        return out_idx;
    }

    fn encodeOIDInt(out: []u8, i: usize) usize {
        var tmp: [100]u8 = undefined;
        var idx: usize = 0;
        var cur = i;
        while (cur > 0) {
            tmp[idx] = @as(u8, @intCast(cur % 128));
            if (idx > 0) {
                tmp[idx] += 0x80;
            }
            cur = cur / 128;
            idx += 1;
        }

        var rev_i: usize = 0;
        while (rev_i < idx) : (rev_i += 1) {
            out[rev_i] = tmp[idx - rev_i - 1];
        }

        return idx;
    }
};

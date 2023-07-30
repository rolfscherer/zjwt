const std = @import("std");
const io = std.io;
const mem = std.mem;

const asn1 = @import("asn1.zig");
const utils = @import("utils.zig");

pub const Error = error{};

// https://www.rfc-editor.org/rfc/rfc5915#section-3
// ECPrivateKey ::= SEQUENCE {
//     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//     privateKey     OCTET STRING,
//     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
//     publicKey  [1] BIT STRING OPTIONAL
// }

// https://datatracker.ietf.org/doc/html/rfc5480#section-2.1.1
// ECParameters ::= CHOICE {
//     namedCurve         OBJECT IDENTIFIER
//     -- implicitCurve   NULL
//     -- specifiedCurve  SpecifiedECDomain
// }
pub const ECPrivateKey = struct {
    privateKey: []u8,
    namedCurve: ?asn1.ObjectIdentifier = null,
    publicKey: []u8 = &([_]u8{}),

    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn decode(reader: anytype, allocator: mem.Allocator) !Self {
        return try asn1.Decoder.decodeSequence(reader, allocator, Self);
    }

    pub fn decodeContent(stream: *asn1.Stream, allocator: mem.Allocator) !Self {
        const reader = stream.reader();

        var t = @as(asn1.Tag, @enumFromInt(try reader.readByte()));
        if (t != .INTEGER) {
            return asn1.Error.InvalidTagType;
        }
        var t_len: usize = try reader.readByte();
        if (t_len != 0x01) { // length is assumed to be 1(u8)
            return asn1.Error.FieldLengthToLarge;
        }
        const ec_version = try reader.readByte();
        if (ec_version != 0x01) {
            return asn1.Error.InvalidFormat;
        }

        t = @as(asn1.Tag, @enumFromInt(try reader.readByte()));
        if (t != .OCTET_STRING) {
            return asn1.Error.InvalidTagType;
        }
        t_len = try asn1.Decoder.decodeLength(reader);
        var privKey = try allocator.alloc(u8, t_len);
        errdefer allocator.free(privKey);
        try reader.readNoEof(privKey);

        var res = Self{
            .privateKey = privKey,
            .allocator = allocator,
        };
        errdefer res.deinit();

        var optional_t = try reader.readByte();
        if (optional_t == 0xA0) { // [0] OPTIONAL
            t_len = try asn1.Decoder.decodeLength(reader);
            // Currently, only 'namedCurve' is supported.
            res.namedCurve = try asn1.ObjectIdentifier.decode(reader, allocator);

            optional_t = reader.readByte() catch @as(u8, 0);
        }

        if (optional_t == 0) {
            return res;
        }

        if (optional_t == 0xA1) { // [1] OPTIONAL
            t_len = try asn1.Decoder.decodeLength(reader);
            const t_key = @as(asn1.Tag, @enumFromInt(try reader.readByte()));
            if (t_key != .BIT_STRING) {
                return asn1.Error.InvalidTagType;
            }
            const key_len = try asn1.Decoder.decodeLength(reader);
            // the first byte of 'BIT STRING' specifies
            // the number of bits not used in the last of the octets
            const b = try reader.readByte();
            if (b != 0x00) {
                // TODO: handle this
                return asn1.Error.InvalidFormat;
            }

            res.publicKey = try allocator.alloc(u8, key_len - 1);
            try reader.readNoEof(res.publicKey);
        }

        return res;
    }

    pub fn deinit(self: Self) void {
        self.allocator.free(self.privateKey);
        if (self.namedCurve) |p| {
            p.deinit();
        }
        if (self.publicKey.len != 0) {
            self.allocator.free(self.publicKey);
        }
    }

    pub fn fromDer(subPath: []const u8, allocator: std.mem.Allocator) !Self {
        const fb = try utils.readFileRelative(subPath, allocator);
        defer fb.deinit();

        var stream = io.fixedBufferStream(fb.items);

        return try Self.decode(stream.reader(), allocator);
    }
};

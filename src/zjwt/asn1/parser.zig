const std = @import("std");
const mem = std.mem;

const pem = @import("pem.zig");

// https://letsencrypt.org/de/docs/a-warm-welcome-to-asn1-and-der/
// https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
// https://github.com/openssl/openssl/blob/fbd23b929609c0b2fe22da97ac349fae5a385027/fuzz/oids.txt

const Array = std.ArrayList(Asn1.Element);

allocator: mem.Allocator,
array: Array,

pub const Parser = @This();

pub const Error = error{
    Asn1FieldHasInvalidLength,
    ImvalidPemFormat,
};

pub const Asn1 = struct {
    pub const Class = enum(u2) {
        universal,
        application,
        context_specific,
        private,

        pub fn phrase(self: Class) []const u8 {
            return switch (self) {
                else => @tagName(self),
            };
        }
    };

    // Bit 6 of the first tag byte is used to indicate whether the value is encoded in primitive form or constructed form.
    // Primitive encoding represents the value directly - for instance, in a UTF8String the value would consist solely of the string itself,
    // in UTF-8 bytes. Constructed encoding represents the value as a concatenation of other encoded values. For instance, as described in
    // the “Indefinite length” section, a UTF8String in constructed encoding would consist of multiple encoded UTF8Strings
    // (each with a tag and length), concatenated together. The length of the overall UTF8String would be the total length, in bytes,
    // of all those concatenated encoded values. Constructed encoding can use either definite or indefinite length. Primitive encoding
    // always uses definite length, because there’s no way to express indefinite length without using constructed encoding.

    // INTEGER, OBJECT IDENTIFIER, and NULL must use primitive encoding. SEQUENCE, SEQUENCE OF, SET, and SET OF must use constructed encoding
    // (because they are inherently concatenations of multiple values). BIT STRING, OCTET STRING, UTCTime, GeneralizedTime, and
    // the various string types can use either primitive encoding or constructed encoding, at the sender’s discretion--
    // in BER. However, in DER all types that have an encoding choice between primitive and constructed must use the primitive encoding.

    pub const PC = enum(u1) {
        primitive,
        constructed,

        pub fn phrase(self: PC) []const u8 {
            return switch (self) {
                else => @tagName(self),
            };
        }
    };

    // The identifier octets shall encode the ASN.1 tag (class and number) of the type of the data value.
    // For tags with a number ranging from zero to 30 (inclusive), the identifier octets shall comprise a single octet
    // encoded as follows:
    // a) bits 8 and 7 shall be encoded to represent the class of the tag as specified in Table 1;
    // b) bit 6 shall be a zero or a one
    // c) bits 5 to 1 shall encode the number of the tag as a binary integer with bit 5 as the most significant bit.
    pub const Identifier = packed struct(u8) {
        tag: Tag,
        pc: PC,
        class: Class,
    };

    pub const Tag = enum(u5) {
        boolean = 1,
        integer = 2,
        bitstring = 3,
        octetstring = 4,
        null = 5,
        object_identifier = 6,
        utf8_string = 8,
        sequence = 16,
        sequence_of = 17,
        printable_string = 19,
        ia5string = 22,
        utc_time = 23,
        generalized_time = 24,
        _,

        pub fn phrase(self: Tag) []const u8 {
            return switch (self) {
                .boolean, .integer, .bitstring, .octetstring, .null, .object_identifier, .utf8_string, .sequence, .sequence_of, .printable_string, .ia5string, .utc_time, .generalized_time => @tagName(self),
                _ => "cont",
            };
        }
    };

    pub const Element = struct {
        identifier: Identifier,
        slice: Slice,

        pub const Slice = struct {
            start: u32,
            end: u32,

            pub const empty: Slice = .{ .start = 0, .end = 0 };
        };

        pub const ParseElementError = error{Asn1FieldHasInvalidLength};

        pub fn parse(bytes: []const u8, index: u32) ParseElementError!Element {
            var i = index;
            const identifier = @as(Identifier, @bitCast(bytes[i]));
            i += 1;
            const size_byte = bytes[i];
            i += 1;
            if ((size_byte >> 7) == 0) {
                return .{
                    .identifier = identifier,
                    .slice = .{
                        .start = i,
                        .end = i + size_byte,
                    },
                };
            }

            const len_size = @as(u7, @truncate(size_byte));
            if (len_size > @sizeOf(u32)) {
                return error.Asn1FieldHasInvalidLength;
            }

            const end_i = i + len_size;
            var long_form_size: u32 = 0;
            while (i < end_i) : (i += 1) {
                long_form_size = (long_form_size << 8) | bytes[i];
            }

            return .{
                .identifier = identifier,
                .slice = .{
                    .start = i,
                    .end = i + long_form_size,
                },
            };
        }
    };
};

pub fn init(allocator: mem.Allocator) Parser {
    return .{
        .allocator = allocator,
        .array = Array.init(allocator),
    };
}

pub fn deinit(parser: *Parser) void {
    parser.array.deinit();
}

pub fn parsePEM(parser: *Parser, content: []const u8) !void {
    if (!pem.isPEMFormatted(content)) {
        return error.ImvalidPemFormat;
    }

    const result = try pem.removePEMMarkers(content, parser.allocator);
    defer result.deinit();

    try parser.parseBase64(result.items);
}

pub fn parseBase64(parser: *Parser, content: []const u8) !void {
    const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");

    var buffer = try parser.allocator.alloc(u8, content.len);
    defer parser.allocator.free(buffer);
    var len = try base64.decode(buffer, content);

    try parser.parseDer(buffer[0..len], 0, @as(u32, @intCast(len)));
}

pub fn parseDer(parser: *Parser, content: []const u8, start: u32, end: u32) !void {
    var index: u32 = start;

    while (index < end) {
        const element = try Asn1.Element.parse(content, index);
        try parser.array.append(element);

        index = element.slice.end;
        std.log.info("Tag={s} PC={s} l={} s={} e={}", .{ element.identifier.tag.phrase(), element.identifier.pc.phrase(), element.slice.end - element.slice.start, element.slice.start, element.slice.end });

        if (element.identifier.pc == .constructed or (element.identifier.tag == .octetstring and content[element.slice.start] == 0x30)) {
            try parser.parseDer(content, element.slice.start, element.slice.end);
        } else {
            switch (element.identifier.tag) {
                .integer => {
                    if (element.slice.end - element.slice.start > 4) {
                        std.log.info("{s}", .{std.fmt.fmtSliceHexLower(content[element.slice.start..element.slice.end])});
                    } else {
                        var int: i64 = 0;
                        for (content[element.slice.start..element.slice.end]) |val| {
                            int <<= 16;
                            int += val;
                        }
                        std.log.info("{d}", .{int});
                    }
                },
                .object_identifier => {
                    std.log.info("{s}", .{std.fmt.fmtSliceHexLower(content[element.slice.start..element.slice.end])});
                },
                else => {},
            }
        }
    }
}

test "basics" {
    std.testing.refAllDecls(@This());
}

test "private key" {
    const t = @import("test.zig");
    var parser = Parser.init(std.testing.allocator);
    defer parser.deinit();

    try parser.parsePEM(t.private_key);
}

const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const crypto = std.crypto;
const ecdsa = std.crypto.sign.ecdsa;
const base64 = std.base64.standard.decoderWithIgnore(" \t\r\n");
const Allocator = mem.Allocator;
const Certificate = crypto.Certificate;
const Bundle = crypto.Certificate.Bundle;

pub const CertUtils = @This();

allocator: Allocator,
bundle: Bundle,
privateKey: std.ArrayList(u8),

pub const Error = error{
    CertificateNotFound,
    MissingBeginnKeyMarker,
    MissingEndKeyMarker,
};

pub fn init(allocator: Allocator) CertUtils {
    return .{
        .allocator = allocator,
        .bundle = .{},
        .privateKey = std.ArrayList(u8).init(allocator),
    };
}

pub fn deinit(certUtils: *CertUtils) void {
    certUtils.bundle.deinit(certUtils.allocator);
    certUtils.privateKey.deinit();
}

pub fn loadCertificate(certUtils: *CertUtils, subPath: []const u8) !void {
    var dirBuffer: [std.fs.MAX_PATH_BYTES]u8 = undefined;
    const cwd = try std.os.getcwd(&dirBuffer);
    const dir = try std.fs.openDirAbsolute(cwd, .{});

    certUtils.bundle.map.clearRetainingCapacity();
    try certUtils.bundle.addCertsFromFilePath(certUtils.allocator, dir, subPath);
}

pub fn getCertificate(certUtils: *CertUtils) !crypto.Certificate.Parsed {
    var it = certUtils.bundle.map.keyIterator();

    if (it.next()) |slice| {
        var subject = certUtils.bundle.bytes.items[slice.start..slice.end];
        var bytes_index = certUtils.bundle.find(subject);

        if (bytes_index) |index| {
            const cert: Certificate = .{
                .buffer = certUtils.bundle.bytes.items,
                .index = index,
            };
            const certificate = cert.parse() catch unreachable;
            return certificate;
        }
    }

    return error.CertificateNotFound;
}

pub fn loadPrivateKey(certUtils: *CertUtils, file: fs.File) ![]const u8 {
    const size = try file.getEndPos();

    const buffer = try certUtils.allocator.alloc(u8, size);
    _ = try file.readAll(buffer);

    const begin_marker = "-----BEGIN PRIVATE KEY-----";
    const end_marker = "-----END PRIVATE KEY-----";

    var start_index: usize = 0;
    if (mem.indexOfPos(u8, buffer, 0, begin_marker)) |begin_marker_start| {
        const key_start = begin_marker_start + begin_marker.len;
        const key_end = mem.indexOfPos(u8, buffer, key_start, end_marker) orelse
            return error.MissingEndKeyMarker;
        start_index = key_end + end_marker.len;
        const encoded_key = mem.trim(u8, buffer[key_start..key_end], " \t\r\n");

        const len = std.base64.standard.Encoder.calcSize(encoded_key.len);
        var key_buffer = try certUtils.allocator.alloc(u8, len);
        defer certUtils.allocator.free(key_buffer);

        _ = try base64.decode(buffer, encoded_key);
        certUtils.privateKey.clearRetainingCapacity();
        try certUtils.privateKey.appendSlice(buffer);
        return certUtils.privateKey.items;
    }
    return error.MissingBeginnKeyMarker;
}

pub fn loadCertificates(certUtils: *CertUtils) !void {
    try certUtils.loadCertificate("certs/ecdsa_prime256v1_cert.pem");
    try certUtils.loadCertificate("certs/ecdsa_secp384r1_cert.pem");

    var it = certUtils.bundle.map.keyIterator();

    while (it.next()) |v| {
        var start = v.start;
        var end = v.end;

        const slice = certUtils.bundle.bytes.items[start..end];
        var bytes_index = certUtils.bundle.find(slice);

        if (bytes_index) |index| {
            const cert: Certificate = .{
                .buffer = certUtils.bundle.bytes.items,
                .index = index,
            };
            const subject = cert.parse() catch unreachable;

            var parsed: ?crypto.Certificate.Parsed = undefined;
            _ = parsed;

            std.log.info("{any}", .{subject.pub_key_algo});

            switch (subject.pub_key_algo) {
                .rsaEncryption => {},
                .X9_62_id_ecPublicKey => |name| {
                    const pk = certUtils.bundle.bytes.items[subject.pub_key_slice.start..subject.pub_key_slice.end];

                    if (name == .secp384r1) {
                        const key = try ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(pk);
                        std.log.info("{any}", .{@TypeOf(key)});
                    } else if (name == .X9_62_prime256v1) {
                        const key = try ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(pk);
                        std.log.info("{any}", .{@TypeOf(key)});
                    } else {
                        std.log.info("{any}", .{name});
                    }
                },
            }
        }
    }
}

test "basics" {
    std.testing.refAllDecls(@This());
}

test "expectError default zig testheader validator " {
    var certUtils = CertUtils.init(std.testing.allocator);
    defer certUtils.deinit();
    try certUtils.loadCertificate("certs/ecdsa_prime256v1_cert.pem");
    const certificate = try certUtils.getCertificate();
    _ = certificate;
}

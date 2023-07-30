const std = @import("std");
const mem = std.mem;
const fs = std.fs;
const crypto = std.crypto;
const ecdsa = std.crypto.sign.ecdsa;
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

test "basics" {
    std.testing.refAllDecls(@This());
}

test "rad cerificate" {
    var certUtils = CertUtils.init(std.testing.allocator);
    defer certUtils.deinit();
    try certUtils.loadCertificate("certs/p384_cert.pem");
    const certificate = try certUtils.getCertificate();

    try std.testing.expectEqual(Certificate.Parsed.PubKeyAlgo.X9_62_id_ecPublicKey, certificate.pub_key_algo);

    const pk = certificate.pubKey();
    _ = pk;
}

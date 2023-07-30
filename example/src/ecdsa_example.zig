const std = @import("std");
const Allocator = std.mem.Allocator;
const zjwt = @import("zjwt");
const utils = zjwt.utils;
const key = zjwt.key;
const bte = @import("big_token_example.zig");

pub fn encodeAndDecode(allocator: Allocator, alg: zjwt.Algorithm, signatureOptions: zjwt.SignatureOptions) !void {
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();

    try bte.createToken(alg, signatureOptions, &buffer, allocator);
    std.debug.print("Token generated. You can validate it on https://jwt.io\n{s}\n", .{buffer.items});
    var token = try bte.vlidateToken(alg, signatureOptions, buffer.items, allocator);
    defer token.deinit();
}

// Public key is derived from private key
fn ecdsa256WithPrivateKey(allocator: Allocator) !void {
    const alg = zjwt.Algorithm.ES256;
    const pk = try key.ECPrivateKey.fromDer("certs/p256_private_key.der", allocator);
    try encodeAndDecode(allocator, alg, .{ .key = pk.privateKey });
}

// Public and private key are read from the key file
fn ecdsa256WithKeyPair(allocator: Allocator) !void {
    const alg = zjwt.Algorithm.ES256;
    const pk = try key.ECPrivateKey.fromDer("certs/p256_key.der", allocator);
    try encodeAndDecode(allocator, alg, .{ .key = pk.privateKey, .publicKey = pk.publicKey });
}

// Public and private key are read from the key file
fn ecdsa384WithKeyPair(allocator: Allocator) !void {
    const alg = zjwt.Algorithm.ES384;
    const pk = try key.ECPrivateKey.fromDer("certs/p384_key.der", allocator);
    try encodeAndDecode(allocator, alg, .{ .key = pk.privateKey, .publicKey = pk.publicKey });
}

fn ecdsa384WithCertificate(allocator: Allocator) !void {
    var certUtils = zjwt.cert_utils.CertUtils.init(allocator);
    defer certUtils.deinit();
    try certUtils.loadCertificate("certs/p384_cert.pem");
    const certificate = try certUtils.getCertificate();
    const publicKey = certificate.pubKey();
    const alg = zjwt.Algorithm.ES384;
    const pk = try key.ECPrivateKey.fromDer("certs/p384_private_key.der", allocator);
    try encodeAndDecode(allocator, alg, .{ .key = pk.privateKey, .publicKey = publicKey });
}

pub fn encodeAndDecodeAll(allocator: Allocator) !void {
    try ecdsa256WithPrivateKey(allocator);
    try ecdsa256WithKeyPair(allocator);
    try ecdsa384WithKeyPair(allocator);
    try ecdsa384WithCertificate(allocator);
}

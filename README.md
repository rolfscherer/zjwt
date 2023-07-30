# JSON Web Tokens (JWT) library

This library implement signing and verification of [JSON Web Tokens][], or JWTs,
based on [RFC 7159][].

The library is implemented in the zig language and only uses the standard libraries.-

[json web tokens]: https://jwt.io/
[rfc 7159]: https://datatracker.ietf.org/doc/html/rfc7519

## Features

-   [x] Sign
-   [x] Verify
-   [x] iss check
-   [x] sub check
-   [x] aud check
-   [x] exp check
-   [x] nbf check
-   [x] iat check
-   [x] jti check
-   [x] typ check

Encryption algorithms:

-   [x] HS256
-   [x] HS384
-   [x] HS512
-   [x] PS256
-   [x] PS384
-   [ ] PS512
-   [ ] RS256
-   [ ] RS384
-   [ ] RS512
-   [ ] ES256
-   [ ] ES256K
-   [ ] ES384
-   [ ] ES512
-   [ ] EdDSA

## Create Token
```zig
fn createToken(alg: zjwt.Algorithm, signatureOptions: zjwt.SignatureOptions, buffer: *std.ArrayList(u8), allocator: Allocator) !void {
    var j = zjwt.ZJwt.init(allocator);

    var token = zjwt.Token.init(allocator);
    defer token.deinit();

    // Builds the header as follows { "typ": "JWT", "alg": "HS256" }
    try token.createDefaultHeader(alg);

    // Builds the payload as follows { "iss": "zjwt", "sub": "username", "iat": 1690702984, "exp": 1690706584 }
    try token.addIssuer(issuer);
    try token.addSubject("username");
    try token.addIssuedAt();
    try token.addExpiresAt(3600);

    // Encodes the header and the token to base64 and creates the signature using the chosen algorithm
    try buffer.appendSlice(try j.encode(alg, signatureOptions, &token));
}
```

## Validate Token
```zig
fn vlidateToken(alg: zjwt.Algorithm, signatureOptions: zjwt.SignatureOptions, tokenBase64: []const u8, allocator: Allocator) !void {
    var j = zjwt.ZJwt.init(allocator);
    var token = zjwt.Token.init(allocator);
    defer token.deinit();

    // The default header validator checks the algorithm and the type
    var headerValidator = try zjwt.validator.createDefaultHeaderValidator(allocator, alg.phrase());
    defer headerValidator.deinit();

    // The default payload validator checks the issuer and the expiration time
    var payloadValidator = try zjwt.validator.createDefaultPayloadValidator(allocator, issuer);

    try j.decode(alg, signatureOptions, .{
        .saveHeader = false, // Do not save the header
        .savePayload = true, // Save the payload 
        .headerValidator = headerValidator, // Validate the header
        .payloadValidator = payloadValidator, // Validate the payload
    }, tokenBase64, &token);

    std.debug.print("Token validated for subject: {s}\n", .{token.payload.get(zjwt.Claims.SUBJECT).?.string});
}
```
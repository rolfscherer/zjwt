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

This code contains various ideas from other projects. For example:

https://github.com/leroycep/zig-jwt

https://github.com/shiguredo/tls13-zig


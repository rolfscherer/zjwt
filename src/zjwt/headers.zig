const std = @import("std");

pub const Headers = @This();

// The "typ" (type) Header Parameter defined by [JWS] and [JWE] is used
// by JWT applications to declare the media type [IANA.MediaTypes] of
// this complete JWT.  This is intended for use by the JWT application
// when values that are not JWTs could also be present in an application
// data structure that can contain a JWT object; the application can use
// this value to disambiguate among the different kinds of objects that
// might be present.  It will typically not be used by applications when
// it is already known that the object is a JWT.  This parameter is
// ignored by JWT implementations; any processing of this parameter is
// performed by the JWT application.  If present, it is RECOMMENDED that
// its value be "JWT" to indicate that this object is a JWT.  While
// media type names are not case sensitive, it is RECOMMENDED that "JWT"
// always be spelled using uppercase characters for compatibility with
// legacy implementations.  Use of this Header Parameter is OPTIONAL.

// Refer RFC 7529 https://datatracker.ietf.org/doc/html/rfc7519#section-5.1
pub const TYPE = "typ";

pub const ALGORITHM = "alg";

pub const TYPE_JWT = "JWT";

test {
    std.testing.refAllDecls(@This());
}

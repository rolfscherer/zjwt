const std = @import("std");

pub fn getSecondsFromMinutes(num: i64) i64 {
    return num * 60;
}

pub fn getSecondsFromHours(num: i64) i64 {
    return num * 60 * 60;
}

pub fn getSecondsFromDays(num: i64) i64 {
    return num * 60 * 60 * 24;
}

test "basics" {
    std.testing.refAllDecls(@This());
}

const std = @import("std");

const UnpackItems = struct {
    int: i32,
    uint: u32,
    short: i8,
    float: f32,
    double: f64,
    big_endian_double: f64,
};

pub fn unpack(base64_bytes: []const u8) !UnpackItems {
    var unpack_items: UnpackItems = .{};

    return unpack_items;
}

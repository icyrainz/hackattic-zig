const std = @import("std");

const Problem = struct {
    bytes: []const u8,
};

const UnpackItems = struct {
    int: i32,
    uint: u32,
    short: i16,
    float: f32,
    double: f64,
    big_endian_double: f64,
};

pub fn solve(input_json: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    const parsedProblem = try std.json.parseFromSlice(Problem, allocator, input_json, .{});
    const unpacked = try unpack(parsedProblem.value.bytes, allocator);

    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();

    try std.json.stringify(unpacked, .{}, array_list.writer());

    return array_list.toOwnedSlice();
}

fn unpack(raw_bytes: []const u8, allocator: std.mem.Allocator) !?UnpackItems {
    var bytes: []u8 = try allocator.alloc(u8, raw_bytes.len);
    defer allocator.free(bytes);

    try std.base64.standard.Decoder.decode(bytes, raw_bytes);

    if (bytes.len < 30) {
        return null;
    }

    // First 4 bytes are int
    const int_slice: [4]u8 = bytes[0..4].*;
    const int_val = std.mem.readInt(i32, &int_slice, .little);
    std.debug.print("int: {d}\n", .{int_val});

    // Next 4 bytes are unsigned int
    const uint_slice: [4]u8 = bytes[4..8].*;
    const uint_val = std.mem.readInt(u32, &uint_slice, .little);
    std.debug.print("uint: {d}\n", .{uint_val});

    // Next 2 bytes are short
    const short_slice: [2]u8 = bytes[8..10].*;
    const short_val = std.mem.readInt(i16, &short_slice, .little);
    std.debug.print("short: {d}\n", .{short_val});

    // Next 4 bytes are float
    const float_slice: [4]u8 = bytes[10..14].*;
    const float_val: f32 = @bitCast(std.mem.readInt(u32, &float_slice, .little));
    std.debug.print("float: {e}\n", .{float_val});

    // Next 8 bytes are double
    const double_slice: [8]u8 = bytes[14..22].*;
    const double_val: f64 = @bitCast(std.mem.readInt(u64, &double_slice, .little));
    std.debug.print("double: {e}\n", .{double_val});

    // Last 8 bytes are double but using big endian
    const double_big_endian_slice: [8]u8 = bytes[22..30].*;
    const double_big_endian_val: f64 = @bitCast(std.mem.readInt(u64, &double_big_endian_slice, .big));
    std.debug.print("double big endian: {e}\n", .{double_big_endian_val});

    // Return the unpacked values
    return UnpackItems{
        .int = int_val,
        .uint = uint_val,
        .short = short_val,
        .float = float_val,
        .double = double_val,
        .big_endian_double = double_big_endian_val,
    };
}

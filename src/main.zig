const std = @import("std");
const help_me_unpack = @import("help-me-unpack.zig");

pub fn main() !void {
    help_me_unpack.unpack("hello".toSlice());
}

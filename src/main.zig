const std = @import("std");
const hackattic = @import("hackattic.zig");
const help_me_unpack = @import("help-me-unpack.zig");

const access_token = "a205ba4ea45be0c8";

fn do_help_me_unpack(allocator: std.mem.Allocator) !void {
    const challenge = hackattic.Challenge.init(allocator, "help_me_unpack", access_token);

    const input = try challenge.get_input_json();
    std.debug.print("json_input: {s}\n", .{input});

    const output = help_me_unpack.solve(input, allocator) catch |err| {
        std.debug.print("Failed to solve\n", .{});
        return err;
    };

    try challenge.submit_output(output);
}

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    try do_help_me_unpack(allocator);
}

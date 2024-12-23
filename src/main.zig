const std = @import("std");
const hackattic = @import("hackattic.zig");
const help_me_unpack = @import("help-me-unpack.zig");
const mini_miner = @import("mini-miner.zig");

const access_token = "a205ba4ea45be0c8";

const Solver = struct {
    name: []const u8,
    solve: *const fn (input_json: []const u8, allocator: std.mem.Allocator) anyerror![]const u8,
};

const HelpMeUnpackSolver = Solver{
    .name = "help_me_unpack",
    .solve = help_me_unpack.solve,
};

const MiniMinerSolver = Solver{
    .name = "mini_miner",
    .solve = mini_miner.solve,
};

const Solvers = [_]*const Solver{
    &HelpMeUnpackSolver,
    &MiniMinerSolver,
};

fn do_solve(challenge_name: []const u8, using_playground: bool, allocator: std.mem.Allocator) !void {
    const challenge = hackattic.Challenge.init(allocator, challenge_name, access_token);

    const input = try challenge.get_input_json();

    var solver: Solver = undefined;
    for (Solvers) |s| {
        if (std.mem.eql(u8, s.name, challenge_name)) {
            solver = s.*;
            break;
        }
    }

    const output = solver.solve(input, allocator) catch |err| {
        std.debug.print("Failed to solve: {}\n", .{err});
        return;
    };
    challenge.submit_output(output, using_playground) catch |err| {
        std.debug.print("Failed to submit_output: {}\n", .{err});
        return;
    };
    return;
}

pub fn main() !void {
    var arena_allocator = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_allocator.deinit();
    const allocator = arena_allocator.allocator();

    const envs = try std.process.getEnvMap(allocator);
    const using_playground = if (std.mem.eql(u8, envs.get("PLAY") orelse "", "1")) true else false;

    try do_solve("mini_miner", using_playground, allocator);
}

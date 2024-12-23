const std = @import("std");

const Block = struct { data: []const [2]std.json.Value, nonce: ?u32 };

const Problem = struct {
    block: Block,
    difficulty: u32,
};

const Solution = struct {
    nonce: ?u32,
};

fn getBlockJsonMinified(block: *const Block, allocator: std.mem.Allocator) ![]const u8 {
    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();

    try std.json.stringify(block, .{}, array_list.writer());

    return array_list.toOwnedSlice();
}

fn getSHA256Hash(block_json: []const u8) ![32]u8 {
    var hashed: [32]u8 = undefined;

    std.crypto.hash.sha2.Sha256.hash(block_json, &hashed, .{});

    return hashed;
}

fn checkDifficulty(sha256_hash: [32]u8, difficulty: u32) !bool {
    const full_bytes = difficulty / 8;
    const remaining_bits = @mod(difficulty, 8);

    for (sha256_hash[0..full_bytes]) |byte| {
        if (byte != 0) return false;
    }

    if (remaining_bits > 0) {
        if (full_bytes > sha256_hash.len) return false;
        const mask: u8 = @as(u8, 0xFF) << @intCast(8 - remaining_bits);
        if ((sha256_hash[full_bytes] & mask) != 0) return false;
    }

    return true;
}

fn mine(block: *Block, difficulty: u32, allocator: std.mem.Allocator) !?u32 {
    var nonce: u32 = 0;
    const max_nonce: u32 = std.math.maxInt(u32);
    while (nonce < max_nonce) {
        block.nonce = nonce;

        const block_json = try getBlockJsonMinified(block, allocator);
        defer allocator.free(block_json);

        const sha256_hash = try getSHA256Hash(block_json);
        const check_diff = try checkDifficulty(sha256_hash, difficulty);

        if (check_diff) {
            return nonce;
        }

        nonce += 1;
    }
    return null;
}

pub fn solve(input_json: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    const parsedProblem = try std.json.parseFromSlice(Problem, allocator, input_json, .{});

    var block = parsedProblem.value.block;
    const difficulty = parsedProblem.value.difficulty;

    const nonce = try mine(&block, difficulty, allocator);

    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();

    try std.json.stringify(Solution{ .nonce = nonce }, .{}, array_list.writer());
    return array_list.toOwnedSlice();
}

test "mine sample" {
    var sample = Block{
        .data = &[_][2]std.json.Value{},
        .nonce = null,
    };

    std.testing.expectEqual(mine(&sample, 8, std.heap.page_allocator), 45);
}

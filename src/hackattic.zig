const std = @import("std");

const url_prefix = "https://hackattic.com/challenges/";

pub const Challenge = struct {
    allocator: std.mem.Allocator,
    challenge_name: []const u8,
    access_token: []const u8,

    const Self = @This();

    var httpClient: std.http.Client = undefined;

    pub fn init(allocator: std.mem.Allocator, challenge_name: []const u8, access_token: []const u8) Self {
        httpClient = std.http.Client{
            .allocator = allocator,
        };

        return .{
            .allocator = allocator,
            .challenge_name = challenge_name,
            .access_token = access_token,
        };
    }

    pub fn get_input_json(self: *const Self) ![]const u8 {
        const url_final = try std.fmt.allocPrint(self.allocator, "{s}{s}/problem?access_token={s}", .{ url_prefix, self.challenge_name, self.access_token });

        var response_body = std.ArrayList(u8).init(self.allocator);
        defer response_body.deinit();

        _ = try httpClient.fetch(.{
            .location = .{
                .url = url_final,
            },
            .method = .GET,
            .response_storage = .{
                .dynamic = &response_body,
            },
        });

        return response_body.toOwnedSlice();
    }

    pub fn submit_output(self: *const Self, output: []const u8, using_playground: bool) !void {
        const url_final = try std.fmt.allocPrint(self.allocator, "{s}{s}/solve?access_token={s}{s}", .{
            url_prefix,
            self.challenge_name,
            self.access_token,
            if (using_playground) "&playground=1" else "",
        });

        var response_body = std.ArrayList(u8).init(self.allocator);
        defer response_body.deinit();

        _ = try httpClient.fetch(.{
            .location = .{
                .url = url_final,
            },
            .method = .POST,
            .payload = output,
            .response_storage = .{
                .dynamic = &response_body,
            },
        });

        std.debug.print("response_body: {s}\n", .{response_body.items});
    }
};

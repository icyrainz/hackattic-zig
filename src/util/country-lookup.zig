const std = @import("std");
const StringHashMap = std.StringHashMap;

pub const CountryCodeLookup = struct {
    const Self = @This();

    countryMap: StringHashMap([]const u8),
    allocator: std.mem.Allocator,

    const Country = struct {
        Name: []const u8,
        Code: []const u8,
    };

    const MAX_FILE_SIZE = 1024 * 1024;

    pub fn init(allocator: std.mem.Allocator, country_code_file_path: []const u8) !Self {
        const file = try std.fs.cwd().openFile(country_code_file_path, .{});
        defer file.close();
        const json_content = try file.readToEndAlloc(allocator, MAX_FILE_SIZE);
        defer allocator.free(json_content);

        const countries = try std.json.parseFromSlice([]Country, allocator, json_content, .{});
        defer countries.deinit();

        var countryMap = StringHashMap([]const u8).init(allocator);
        for (countries.value) |country| {
            const name_copy = try allocator.dupe(u8, country.Name);
            const code_copy = try allocator.dupe(u8, country.Code);
            try countryMap.put(name_copy, code_copy);
        }

        return .{
            .countryMap = countryMap,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.countryMap.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.countryMap.deinit();
    }

    pub fn getCountryCode(self: *Self, country_name: []const u8) ?[]const u8 {
        return self.countryMap.get(country_name);
    }

    pub fn addCustomCountryCode(self: *Self, country_name: []const u8, country_code: []const u8) !void {
        if (self.countryMap.contains(country_name)) {
            return error.CountryAlreadyExists;
        }

        if (country_code.len != 2) {
            return error.InvalidCountryCode;
        }

        const name_copy = try self.allocator.dupe(u8, country_name);
        const code_copy = try self.allocator.dupe(u8, country_code);
        try self.countryMap.put(name_copy, code_copy);
    }
};

test "Country code lookup" {
    var country_lookup = try CountryCodeLookup.init(
        std.testing.allocator,
        "data/country_code.json",
    );
    defer country_lookup.deinit();

    try std.testing.expectEqualStrings(
        "US",
        country_lookup.getCountryCode("United States").?,
    );

    try country_lookup.addCustomCountryCode("U.S.A.", "US");

    try std.testing.expectEqualStrings(
        "US",
        country_lookup.getCountryCode("U.S.A.").?,
    );

    try std.testing.expectError(
        error.CountryAlreadyExists,
        country_lookup.addCustomCountryCode("U.S.A.", "US"),
    );

    try std.testing.expectError(
        error.InvalidCountryCode,
        country_lookup.addCustomCountryCode("United", "USA"),
    );
}

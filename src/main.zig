const std = @import("std");
const solver = @import("solver.zig");

const country_lookup = @import("util/country-lookup.zig");

pub fn main() !void {
    try solver.solve("tales_of_ssl");
}

test {
    _ = country_lookup;
}

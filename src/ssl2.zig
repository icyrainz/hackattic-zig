const std = @import("std");
const CountryCodeLookup = @import("util/country-lookup.zig").CountryCodeLookup;

const Data = struct {
    domain: []const u8,
    serial_number: []const u8,
    country: []const u8,
};

const Problem = struct {
    private_key: []const u8,
    required_data: Data,
};

const Solution = struct {
    certificate: []const u8,
};

fn createPrivateKeyPEMFile(
    allocator: std.mem.Allocator,
    private_key: []const u8,
    file_name: []const u8,
) !void {
    var file = try std.fs.cwd().createFile(file_name, .{ .truncate = true });
    const private_key_header = "-----BEGIN RSA PRIVATE KEY-----";
    const private_key_footer = "-----END RSA PRIVATE KEY-----";

    const body = try std.fmt.allocPrint(
        allocator,
        "{s}\n{s}\n{s}\n",
        .{
            private_key_header,
            private_key,
            private_key_footer,
        },
    );

    file.writeAll(body) catch return error.WriteFailed;
}

fn readCertificateFile(
    allocator: std.mem.Allocator,
    file_name: []const u8,
) ![]const u8 {
    var file = try std.fs.cwd().openFile(file_name, .{});
    defer file.close();

    var cert_body = std.ArrayList(u8).init(allocator);
    defer cert_body.deinit();

    var buf_reader = std.io.bufferedReader(file.reader());
    var in_stream = buf_reader.reader();
    var buf: [1024]u8 = undefined;
    while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
        if (line.len > 0 and line[0] == '-' and line[1] == '-') {
            continue;
        }

        try cert_body.appendSlice(line);
    }

    return cert_body.toOwnedSlice();
}

fn runOpenSSLCLI(
    private_key_file_name: []const u8,
    domain: []const u8,
    serial_number: []const u8,
    country: []const u8,
    out_cert_file_name: []const u8,
    allocator: std.mem.Allocator,
) ![]const u8 {
    const subject = try std.fmt.allocPrint(allocator, "/C={s}/CN={s}", .{ country, domain });
    const days = std.fmt.comptimePrint("{d}", .{30});

    const openssl_args = [_][]const u8{
        "openssl",     "req",
        "-new",        "-x509",
        "-key",        private_key_file_name,
        "-out",        out_cert_file_name,
        "-subj",       subject,
        "-set_serial", serial_number,
        "-days",       days,
    };

    var openssl_process = std.process.Child.init(&openssl_args, allocator);
    const ret = try openssl_process.spawnAndWait();
    std.debug.print("DEBUGPRINT[4]: ssl2.zig:50: ret={any}\n", .{ret});

    return "test";
}

pub fn solve(input_json: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    const parsed_input = try std.json.parseFromSlice(Problem, allocator, input_json, .{});
    defer parsed_input.deinit();

    var country_code_lookup =
        try CountryCodeLookup.init(
        allocator,
        "data/country_code.json",
    );
    const country_code = country_code_lookup.getCountryCode(
        parsed_input.value.required_data.country,
    ) orelse return error.CountryNotFound;

    const private_key_file_name = "runtime/private_key.pem";
    const out_cert_file_name = "runtime/certificate.crt";

    _ = try createPrivateKeyPEMFile(
        allocator,
        parsed_input.value.private_key,
        private_key_file_name,
    );

    _ = try runOpenSSLCLI(
        private_key_file_name,
        parsed_input.value.required_data.domain,
        parsed_input.value.required_data.serial_number,
        country_code,
        out_cert_file_name,
        allocator,
    );

    const cert = try readCertificateFile(
        allocator,
        out_cert_file_name,
    );

    var array_list = std.ArrayList(u8).init(allocator);
    defer array_list.deinit();

    try std.json.stringify(
        Solution{ .certificate = cert },
        .{},
        array_list.writer(),
    );
    return array_list.toOwnedSlice();
}

const test_json =
    \\{"private_key": "MIICWwIBAAKBgQCxw875JE2aKhYC8gJ/D8cDWVNVFx9SnZ3AtonEpbIGoSNGx+VlIE6f/WZ/n8D3P5SmkuXRHjzVvcXT5s1YCf5tI1ORGh36+fWsB6JsUj4NiTfjzZiHz48FP7VyfVRG87jln1yP4OTyDrhihCrfe3uUFb+wXPwnX3eCwTXn1X4q6wIDAQABAoGAEbLaH4oSw9+e02o+/2GVweqZ1mX382TH+RDzhIWuxOQ0O+7ZEwl1ao5zLw+7yaIl7bPAd+KX0fwT/zYCidps30wvb0YbMAkrz8T7rNaxjgwY+cVnNk9Ep4VrzLZy/fa2EfIst3m6yAsOUVe4r6WbcEypX4pbIKvZd7xLxvC3MkECQQDrP5lXiR82kvbCuDB8Uii57VxoPBtqukbZAvnYafIYOwEoct3nHT35W/397r9TLba/bnsCF/Dzq+CrdEWY6eiLAkEAwXIcWAs4k3y47Q2hKW9CKQ6VvZkrIR1zvIcm6R153c4jiu9v43w6CKKQ73Vkc6s0jL9KUQSAOHjn0ASYrvqzIQJAAPkHWkxP27rp2E5IrQrt7i7kFe5BssRIbLdNby6o+J6t14v6DO2bBv/xYe5tzhs/STVcvtp4fZl1WWAmtYYqFwJAWd7YujKkWyjThRYS7HwK4aYr/QSe2+ih71Fey2htSJXPP2nTsnzxPTfBW+5O98nvRQBN12ve4d2R3Lt177z64QJAJ2Z7ClAJVJO1cTs2xs2asmKXVMFg5UnWXFqo8mNoX6Y0LDtYUza0kVgL2xheSrvPBkriSxptMaoVDH9NEFI+UQ==", "required_data": {"domain": "proud-glade-9680.gov", "serial_number": "0x5eaf00d", "country": "Tokelau Islands"}}
;

test "runOpenSSLCLI" {
    const cert = try solve(test_json, std.testing.allocator);
    std.debug.print("DEBUGPRINT[10]: ssl2.zig:134: cert={any}\n", .{cert});
}

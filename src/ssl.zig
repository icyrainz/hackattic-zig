const std = @import("std");

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

const Asn1Tag = enum(u8) {
    Sequence = 0x30,
    Set = 0x31,
    Integer = 0x02,
    ObjectIdentifier = 0x06,
    PrintableString = 0x13,
    UtcTime = 0x17,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ContextSpecific0 = 0xA0,
    ContextSpecific3 = 0xA3,

    pub fn description(self: Asn1Tag) []const u8 {
        return switch (self) {
            .Sequence => "SEQUENCE",
            .Set => "SET",
            .Integer => "INTEGER",
            .ObjectIdentifier => "OBJECT IDENTIFIER",
            .PrintableString => "PRINTABLE STRING",
            .UtcTime => "UTC TIME",
            .BitString => "BIT STRING",
            .OctetString => "OCTET STRING",
            .Null => "NULL",
            .ContextSpecific0 => "[0] EXPLICIT",
            .ContextSpecific3 => "[3] EXPLICIT",
        };
    }
};

const Tlv = struct {
    tag: Asn1Tag,
    length: u32,
    value: []const u8,
};

const Validity = struct {
    not_before: []const u8,
    not_after: []const u8,
};

const Asn1Writer = struct {
    const Self = @This();

    list: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .list = std.ArrayList(u8).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        self.list.deinit();
    }

    fn writeTag(self: *Self, tag: Asn1Tag) !void {
        try self.list.append(@intFromEnum(tag));
    }

    fn writeLength(self: *Self, length: u32) !void {
        if (length < 128) {
            try self.list.append(@intCast(length));
            return;
        }

        const bytes_needed = (32 - @clz(length) + 7) / 8;

        try self.list.append(@as(u8, 0x80) | bytes_needed);

        // Shift the length byte and byte and mask to get the last byte and write
        var i: u8 = bytes_needed;
        while (i > 0) : (i -= 1) {
            const shift: u5 = @intCast((i - 1) * 8);
            try self.list.append(@intCast((length >> shift) & 0xFF));
        }
    }

    fn writeValue(self: *Self, value: []const u8) !void {
        try self.list.appendSlice(value);
    }

    pub fn writeTlv(self: *Self, tlv: Tlv) !void {
        try self.writeTag(tlv.tag);
        try self.writeLength(tlv.length);
        try self.writeValue(tlv.value);
    }

    /// Maximum length of an integer is 20 bytes
    pub fn writeInteger(self: *Self, value: []const u8) !void {
        if (value.len == 0 or value.len > 20) {
            return error.OutOfRange;
        }

        try self.writeTag(.Integer);
        try self.writeLength(@intCast(value.len));
        try self.writeValue(value);
    }

    pub fn writeOid(self: *Self, oid: []const u8) !void {
        try self.writeTag(.ObjectIdentifier);
        try self.writeLength(@intCast(oid.len));
        try self.writeValue(oid);
    }

    pub fn writeUtcTime(self: *Self, time: []const u8) !void {
        try self.writeTag(.UtcTime);
        try self.writeLength(@intCast(time.len));
        try self.writeValue(time);
    }
};

/// TBSCertificate ::= SEQUENCE {
///     version         [0]  EXPLICIT Version DEFAULT v1,
///     serialNumber         CertificateSerialNumber,
///     signature           AlgorithmIdentifier,
///     issuer              Name,
///     validity            Validity,
///     subject             Name,
///     subjectPublicKeyInfo SubjectPublicKeyInfo,
///     issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
///     subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
///     extensions      [3]  EXPLICIT Extensions OPTIONAL
/// }
const TBSCertificate = struct {
    const Self = @This();

    domain: []const u8,
    serial_number: []const u8,
    country: []const u8,
    validity: Validity,

    pub fn writeCert(self: *const Self, allocator: std.mem.Allocator) ![]const u8 {
        var writer = Asn1Writer.init(allocator);
        defer writer.deinit();

        try self.writeToAsn1Writer(&writer);
        return writer.list.toOwnedSlice();
    }

    fn getLenVersion(_: *const Self, _: u8) u32 {
        return 3 + 2;
    }
    fn writeVersion(_: *const Self, writer: *Asn1Writer, version: u8) !void {
        try writer.writeTag(Asn1Tag.ContextSpecific0);
        // Version TLVs are always 3 bytes long
        try writer.writeLength(3);
        try writer.writeInteger(&[_]u8{version});
    }

    fn getLenSerial(_: *const Self, serial: []const u8) u32 {
        return @intCast(serial.len + 2);
    }
    fn writeSerial(_: *const Self, writer: *Asn1Writer, serial: []const u8) !void {
        try writer.writeTag(Asn1Tag.Integer);
        try writer.writeLength(@intCast(serial.len));
        try writer.writeValue(serial);
    }

    fn getLenSignature(_: *const Self) u32 {
        return 11 + 2;
    }
    fn writeSignature(_: *const Self, writer: *Asn1Writer) !void {
        try writer.writeTag(Asn1Tag.Sequence);
        try writer.writeLength(11);

        // The OID for SHA256-RSA is 1.2.840.113549.1.1.11
        try writer.writeOid(&[_]u8{ 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B });
        try writer.writeTag(.Null);
        try writer.writeLength(0);
    }

    fn getLenValidity(_: *const Self, validity: Validity) u32 {
        return @intCast(validity.not_before.len + 2 + validity.not_after.len + 2 + 2);
    }
    fn writeValidity(_: *const Self, writer: *Asn1Writer, validity: Validity) !void {
        try writer.writeTag(.Sequence);
        const total_len = validity.not_before.len + validity.not_after.len + 4; // Add tag and length bytes
        try writer.writeLength(@intCast(total_len));

        try writer.writeUtcTime(validity.not_before);
        try writer.writeUtcTime(validity.not_after);
    }

    fn getLenName(_: *const Self, country: []const u8, domain: ?[]const u8) u32 {
        var total_len: u32 = 0;

        // Country SET length calculation
        const country_oid_len: u8 = 3; // OID for country (0x55, 0x04, 0x06)
        const country_set_content: u32 = @intCast(country_oid_len + 2 + country.len + 2); // OID TLV + String TLV
        total_len += country_set_content + 2; // Add SET tag and length bytes

        // Domain SET length calculation (if provided)
        if (domain) |dom| {
            const domain_oid_len: u8 = 3; // OID for common name (0x55, 0x04, 0x03)
            const domain_set_content: u32 = @intCast(domain_oid_len + 2 + dom.len + 2); // OID TLV + String TLV
            total_len += domain_set_content + 2; // Add SET tag and length bytes
        }

        return total_len + 2; // Add SEQUENCE tag and length bytes
    }

    fn writeName(self: *const Self, writer: *Asn1Writer, country: []const u8, domain: ?[]const u8) !void {
        try writer.writeTag(.Sequence);
        const sequence_len = self.getLenName(country, domain) - 2; // Subtract SEQUENCE tag and length bytes
        try writer.writeLength(sequence_len);

        // Write country
        try writer.writeTag(.Set);
        const country_set_len: u32 = @intCast(3 + 2 + country.len + 2); // OID TLV + String TLV
        try writer.writeLength(country_set_len);
        try writer.writeOid(&[_]u8{ 0x55, 0x04, 0x06 }); // countryName OID
        try writer.writeTag(.PrintableString);
        try writer.writeLength(@intCast(country.len));
        try writer.writeValue(country);

        // Write domain if provided
        if (domain) |dom| {
            try writer.writeTag(.Set);
            const domain_set_len: u32 = @intCast(3 + 2 + dom.len + 2); // OID TLV + String TLV
            try writer.writeLength(domain_set_len);
            try writer.writeOid(&[_]u8{ 0x55, 0x04, 0x03 }); // commonName OID
            try writer.writeTag(.PrintableString);
            try writer.writeLength(@intCast(dom.len));
            try writer.writeValue(dom);
        }
    }

    pub fn writeToAsn1Writer(self: *const Self, writer: *Asn1Writer) !void {
        try writer.writeTag(.Sequence);
        var total_length: u32 = 0;

        total_length += self.getLenVersion(2);
        total_length += self.getLenSerial(self.serial_number);
        total_length += self.getLenSignature();
        total_length += self.getLenName(self.country, null);
        total_length += self.getLenValidity(self.validity);
        total_length += self.getLenName(self.country, self.domain);

        try writer.writeLength(total_length);

        try self.writeVersion(writer, 2);
        try self.writeSerial(writer, self.serial_number);
        try self.writeSignature(writer);
        try self.writeName(writer, self.country, null); // Issuer
        try self.writeValidity(writer, self.validity);
        try self.writeName(writer, self.country, self.domain); // Subject
    }
};

const c = @cImport({
    @cDefine("_POSIX_C_SOURCE", "200809L");
    @cDefine("__FILE__", "\"ssl.zig\"");
    @cDefine("__LINE__", "0");
    @cInclude("openssl/x509.h");
    @cInclude("openssl/x509v3.h");
    @cInclude("openssl/pem.h");
    @cInclude("openssl/err.h");
});

pub fn createX509CertificateOpenSSL(
    domain: []const u8,
    serial_number: []const u8,
    country: []const u8,
    validity: Validity,
    allocator: std.mem.Allocator,
) ![]u8 {
    const x509 = c.X509_new() orelse return error.X509CreationFailed;
    defer c.X509_free(x509);

    _ = c.X509_set_version(x509, 2);

    // Set serial number
    const serial = c.BN_bin2bn(serial_number.ptr, @intCast(serial_number.len), null) orelse return error.SerialNumberCreationFailed;
    defer c.BN_free(serial);
    const asn1_serial = c.BN_to_ASN1_INTEGER(serial, null) orelse return error.SerialNumberConversionFailed;
    defer c.ASN1_INTEGER_free(asn1_serial);
    if (c.X509_set_serialNumber(x509, asn1_serial) != 1) return error.SerialNumberSetFailed;

    // Create and set subject and issuer names
    const name = c.X509_NAME_new() orelse return error.X509NameCreationFailed;
    defer c.X509_NAME_free(name);

    // Add country
    if (c.X509_NAME_add_entry_by_txt(name, "C", c.MBSTRING_ASC, country.ptr, @intCast(country.len), -1, 0) != 1) return error.CountryAddFailed;

    if (c.X509_NAME_add_entry_by_txt(name, "CN", c.MBSTRING_ASC, domain.ptr, @intCast(domain.len), -1, 0) != 1) return error.DomainAddFailed;

    _ = c.X509_set_subject_name(x509, name);
    _ = c.X509_set_issuer_name(x509, name);

    // Set validity period
    const not_before = c.ASN1_TIME_new() orelse return error.ASN1TimeCreationFailed;
    defer c.ASN1_TIME_free(not_before);
    const not_after = c.ASN1_TIME_new() orelse return error.ASN1TimeCreationFailed;
    defer c.ASN1_TIME_free(not_after);

    _ = c.ASN1_TIME_set_string(not_before, validity.not_before.ptr);
    _ = c.ASN1_TIME_set_string(not_after, validity.not_after.ptr);

    _ = c.X509_set1_notBefore(x509, not_before);
    _ = c.X509_set1_notAfter(x509, not_after);

    // Write the certificate to memory in DER format
    var out_buffer: [*c]u8 = undefined;
    const cert_len = c.i2d_X509(x509, &out_buffer);
    if (cert_len <= 0) {
        const err = c.ERR_get_error();
        const err_str = c.ERR_error_string(err, null);
        std.debug.print("OpenSSL error: {s}\n", .{err_str});
        return error.X509CertificateEncodingFailed;
    }
    defer c.OPENSSL_free(out_buffer);

    // Copy the certificate to Zig-managed buffer
    var cert_bytes = try allocator.alloc(u8, @intCast(cert_len));
    @memcpy(cert_bytes[0..@intCast(cert_len)], out_buffer[0..@intCast(cert_len)]);

    return cert_bytes;
}

pub fn solve(input_json: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    const parsedProblem = try std.json.parseFromSlice(Problem, allocator, input_json, .{});

    const valid_before = std.time.timestamp();
    var buffer: [20]u8 = undefined;
    const timestamp_before = try std.fmt.bufPrint(&buffer, "{d}Z", .{valid_before});
    const valid_after = valid_before + 30 * 24 * 60 * 60;
    const timestamp_after = try std.fmt.bufPrint(&buffer, "{d}Z", .{valid_after});

    const cert = TBSCertificate{ .domain = parsedProblem.value.required_data.domain, .serial_number = parsedProblem.value.required_data.serial_number, .country = parsedProblem.value.required_data.country, .validity = Validity{
        .not_before = timestamp_before,
        .not_after = timestamp_after,
    } };

    const cert_bytes = try cert.writeCert(allocator);
    defer allocator.free(cert_bytes);

    const base64_len = std.base64.standard.Encoder.calcSize(cert_bytes.len);
    const base64_buf = try allocator.alloc(u8, base64_len);
    defer allocator.free(base64_buf);

    _ = std.base64.standard.Encoder.encode(base64_buf, cert_bytes);

    const solution = Solution{ .certificate = base64_buf };
    const encoded_cert_json = try std.json.stringifyAlloc(allocator, solution, .{});
    std.debug.print("DEBUGPRINT[1]: ssl.zig:262: encoded_cert_json={s}\n", .{encoded_cert_json});

    _ = try createX509CertificateOpenSSL(cert.domain, cert.serial_number, cert.country, cert.validity, allocator);

    return encoded_cert_json;
}

const testing = std.testing;

test "ASN.1 Tag encoding" {
    const tag = Asn1Tag.Sequence;
    try testing.expectEqual("SEQUENCE", tag.description());
}

test "ASN.1 writer short length" {
    var writer = Asn1Writer.init(std.testing.allocator);
    defer writer.deinit();

    const tlv = Tlv{
        .tag = Asn1Tag.Integer,
        .length = 1,
        .value = &[_]u8{0x42},
    };

    try writer.writeTlv(tlv);
    try std.testing.expectEqualSlices(u8, writer.list.items, &[_]u8{ @intFromEnum(Asn1Tag.Integer), 1, 0x42 });
}

test "ASN.1 writer long length" {
    const allocator = std.testing.allocator;
    var writer = Asn1Writer.init(allocator);
    defer writer.deinit();

    const long_value = try allocator.alloc(u8, 256);
    defer allocator.free(long_value);
    @memset(long_value, 0xAA);

    const tlv = Tlv{
        .tag = Asn1Tag.OctetString,
        .length = 256,
        .value = long_value,
    };

    try writer.writeTlv(tlv);
    try std.testing.expectEqualSlices(
        u8,
        &[_]u8{ @intFromEnum(Asn1Tag.OctetString), 0x82, 0x01, 0x00 },
        writer.list.items[0..4],
    );

    try std.testing.expectEqual(@as(u32, 260), writer.list.items.len);
}

fn createTestCert() TBSCertificate {
    return TBSCertificate{
        .domain = "example.com",
        .serial_number = &[_]u8{ 0x01, 0x02, 0x03, 0x04 },
        .country = "US",
        .validity = .{
            .not_before = "230101000000Z",
            .not_after = "240101000000Z",
        },
    };
}

test "TBSCertificate validity period" {
    const cert = createTestCert();

    var writer = Asn1Writer.init(std.testing.allocator);
    defer writer.deinit();

    try cert.writeValidity(&writer, cert.validity);

    // Verify sequence tag and length
    try std.testing.expectEqual(@as(u8, @intFromEnum(Asn1Tag.Sequence)), writer.list.items[0]);
    try std.testing.expectEqual(@as(u8, 30), writer.list.items[1]); // Total length

    // Verify UTC time tags
    try std.testing.expectEqual(@as(u8, @intFromEnum(Asn1Tag.UtcTime)), writer.list.items[2]);
    try std.testing.expectEqual(@as(u8, @intFromEnum(Asn1Tag.UtcTime)), writer.list.items[17]);
}

test "TBSCertificate create cert" {
    const testCert = createTestCert();
    // std.debug.print("cert value: {any}\n", .{testCert});

    var writer = Asn1Writer.init(std.testing.allocator);
    defer writer.deinit();

    try testCert.writeToAsn1Writer(&writer);
    // std.debug.print("writer list: {any}\n", .{writer.list.items});
}

test "Compare TBSCertificate with X509Certificate created from OpenSSL lib" {
    const testCert = createTestCert();

    var writer = Asn1Writer.init(std.testing.allocator);
    defer writer.deinit();

    try testCert.writeToAsn1Writer(&writer);

    const tbs_cert_bytes = try writer.list.toOwnedSlice();
    defer std.testing.allocator.free(tbs_cert_bytes);
    std.debug.print("DEBUGPRINT[2]: ssl.zig:456: tbs_cert_bytes={any}\n", .{tbs_cert_bytes});
    const x509_openssl_cert_bytes = try createX509CertificateOpenSSL(testCert.domain, testCert.serial_number, testCert.country, testCert.validity, std.testing.allocator);
    std.debug.print("DEBUGPRINT[3]: ssl.zig:458: x509_openssl_cert_bytes={any}\n", .{x509_openssl_cert_bytes});
}

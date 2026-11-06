use gcp_private_json::{atomic, json};

pub fn event_id(bytes: [u8; 38]) {
    assert((bytes[0] == 34) & (bytes[37] == 34), "Expected quoted event ID");
    for i in 0..36 {
        let c = bytes[i + 1];
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) {
            assert(c == 45, "Invalid event ID delimiter");
        } else {
            assert(((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)), "Invalid event ID digit");
        }
    }
}

pub fn role_name<let N: u32>(bytes: [u8; N], length: u32) {
    assert((length >= 3) & (length <= 66) & (length <= N), "Invalid role length");
    assert((bytes[0] == 34) & (bytes[length - 1] == 34), "Expected quoted role");
    for i in 1..N {
        if i < length - 1 {
            let c = bytes[i];
            assert(((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122)) | ((c >= 48) & (c <= 57)) |
                (c == 95) | (c == 43) | (c == 61) | (c == 44) | (c == 46) | (c == 64) | (c == 45), "Invalid role byte");
        }
    }
}

// Normalize a JSON decimal/exponent without floating point. Keep the fractional
// remainder as a sticky bit so a value just outside the 1 ms boundary cannot round in.
fn milliseconds<let N: u32>(bytes: [u8; N], length: u32) -> (bool, u64, bool) {
    assert(atomic::json_atom(bytes, length) == 2, "Expected numeric event time");
    let negative = bytes[0] == 45;
    let mut count = 0u32;
    let mut first = N;
    let mut integer_digits = 0u32;
    let mut point = false;
    let mut exponent_part = false;
    let mut exponent_negative = false;
    let mut exponent = 0u32;
    let mut mantissa_end = length;
    for i in 0..N {
        if (i < length) & !((i == 0) & negative) {
            let c = bytes[i];
            if (c == 101) | (c == 69) { exponent_part = true; mantissa_end = i; }
            else if exponent_part {
                if c == 45 { exponent_negative = true; }
                else if c != 43 {
                    // Larger magnitudes cannot affect a bounded timestamp comparison.
                    exponent = std::cmp::min(exponent * 10 + (c - 48) as u32, N + 32);
                }
            } else if c == 46 { point = true; }
            else {
                if (first == N) & (c != 48) { first = count; }
                count += 1;
                if !point { integer_digits += 1; }
            }
        }
    }
    let shift = if exponent_negative { -(exponent as i32) } else { exponent as i32 };
    let position = integer_digits as i32 + 3 + shift - first as i32;
    let mut whole = 0u64;
    let mut fraction = false;
    if first < count {
        assert(position <= 15, "Event time outside calendar range");
        let mut digit_index = 0u32;
        for i in 0..N {
            let c = bytes[i];
            if (i < mantissa_end) & (c >= 48) & (c <= 57) {
                if digit_index >= first {
                    if digit_index as i32 - first as i32 < position { whole = whole * 10 + (c - 48) as u64; }
                    else if c != 48 { fraction = true; }
                }
                digit_index += 1;
            }
        }
        let padding = position - (count as i32 - first as i32);
        for i in 0..15 { if (i as i32) < padding { whole *= 10; } }
    }
    (negative, whole, fraction)
}

pub fn timestamps<let T: u32, let N: u32>(
    timestamp: [u8; T], timestamp_length: u32, number: [u8; N], number_length: u32,
    epoch_ms: u64, cutoff_ms: u64,
) {
    assert((timestamp_length == 22) | ((timestamp_length >= 24) & (timestamp_length <= 26)), "AWS timestamp precision");
    assert((epoch_ms <= 253402300799999) & (cutoff_ms <= 253402300799999), "Event time outside calendar range");
    // Intersect two existing inclusive windows at epoch_ms to prove the private
    // calendar/epoch equality without duplicating GCP's leap-year/date conversion.
    json::timestamp_atom(timestamp, timestamp_length, epoch_ms, 7);
    json::timestamp_atom(timestamp, timestamp_length, epoch_ms + 604800000, 7);
    json::timestamp_atom(timestamp, timestamp_length, cutoff_ms, 90);
    let (negative, whole, fraction) = milliseconds(number, number_length);
    if negative {
        assert((epoch_ms == 0) | (epoch_ms == 1), "Outer event time mismatch");
        let upper = 1 - epoch_ms;
        assert((whole < upper) | ((whole == upper) & !fraction), "Outer event time mismatch");
    } else {
        let lower = if epoch_ms == 0 { 0 } else { epoch_ms - 1 };
        let upper = epoch_ms + 1;
        assert((whole >= lower) & ((whole < upper) | ((whole == upper) & !fraction)), "Outer event time mismatch");
    }
}

#[test]
fn event_ids_and_role_symbols() {
    event_id("\"aaaaaaaa-1234-ffff-0000-0123456789ab\"".as_bytes());
    let role = "\"a_A09+=,.@-\"".as_bytes(); role_name(role, role.len());
}

#[test(should_fail_with = "Invalid event ID digit")]
fn uppercase_event_id_rejects() { event_id("\"Aaaaaaaa-1234-ffff-0000-0123456789ab\"".as_bytes()); }

#[test(should_fail_with = "Invalid event ID delimiter")]
fn event_id_delimiter_rejects() { event_id("\"aaaaaaaa_1234-ffff-0000-0123456789ab\"".as_bytes()); }

#[test(should_fail_with = "Invalid role byte")]
fn role_path_rejects() { role_name("\"path/role\"".as_bytes(), 11); }

#[test(should_fail_with = "Invalid role length")]
fn empty_role_rejects() { role_name("\"\"".as_bytes(), 2); }

#[test]
fn maximum_role_length_accepts() {
    let mut role = [65u8; 66]; role[0] = 34; role[65] = 34;
    role_name(role, 66);
}

#[test(should_fail_with = "Invalid role length")]
fn oversized_role_rejects() { role_name([65u8; 67], 67); }

#[test]
fn decimal_and_exponent_times_preserve_submillisecond_remainders() {
    assert(milliseconds("1709164800.001".as_bytes(), 14) == (false, 1709164800001, false));
    assert(milliseconds("1.709164800001e9".as_bytes(), 16) == (false, 1709164800001, false));
    assert(milliseconds("17091648000010001e-7".as_bytes(), 20) == (false, 1709164800001, true));
    assert(milliseconds("-0e999999999999999".as_bytes(), 18) == (true, 0, false));
    assert(milliseconds("1e-999999999999999".as_bytes(), 18) == (false, 0, true));
}

#[test]
fn leading_fraction_zeros_and_signed_exponents() {
    let a = "0.000001e+6".as_bytes(); assert(milliseconds(a, a.len()) == (false, 1000, false));
    let b = "100e-2".as_bytes(); assert(milliseconds(b, b.len()) == (false, 1000, false));
    let c = "-0.001".as_bytes(); assert(milliseconds(c, c.len()) == (true, 1, false));
}

#[test(should_fail)]
fn malformed_number_rejects() { let _ = milliseconds("01".as_bytes(), 2); }

#[test(should_fail_with = "Event time outside calendar range")]
fn overflowing_number_rejects() {
    let n = "1e99999999999999999999".as_bytes(); let _ = milliseconds(n, n.len());
}

#[test]
fn leap_day_and_inclusive_one_millisecond_tolerance() {
    let t = "\"2024-02-29T00:00:00Z\"".as_bytes();
    timestamps(t, t.len(), "1709164800.001".as_bytes(), 14, 1709164800000, 1709164800000);
    timestamps(t, t.len(), "1709164799.999".as_bytes(), 14, 1709164800000, 1709164800000);
}

#[test(should_fail_with = "Outer event time mismatch")]
fn tiny_fraction_past_tolerance_rejects() {
    let t = "\"2024-02-29T00:00:00Z\"".as_bytes();
    let n = "1709164800.00100000000001".as_bytes();
    timestamps(t, t.len(), n, n.len(), 1709164800000, 1709164800000);
}

#[test(should_fail_with = "Outer event time mismatch")]
fn tiny_fraction_before_tolerance_rejects() {
    let t = "\"2024-02-29T00:00:00Z\"".as_bytes();
    let n = "1709164799.99899999999999".as_bytes();
    timestamps(t, t.len(), n, n.len(), 1709164800000, 1709164800000);
}

#[test(should_fail_with = "Timestamp after window")]
fn dishonest_private_epoch_rejects() {
    let t = "\"2024-02-29T00:00:00.001Z\"".as_bytes();
    timestamps(t, t.len(), "1709164800".as_bytes(), 10, 1709164800000, 1709164800000);
}

#[test(should_fail_with = "Invalid calendar day")]
fn normalized_invalid_calendar_date_rejects() {
    let t = "\"2023-02-29T00:00:00Z\"".as_bytes();
    timestamps(t, t.len(), "1677628800".as_bytes(), 10, 1677628800000, 1677628800000);
}

#[test(should_fail_with = "AWS timestamp precision")]
fn unsupported_iso_precision_rejects() {
    let t = "\"2024-02-29T00:00:00.0001Z\"".as_bytes();
    timestamps(t, t.len(), "1709164800".as_bytes(), 10, 1709164800000, 1709164800000);
}

#[test]
fn inclusive_retention_edges_accept() {
    let t = "\"2024-02-29T00:00:00Z\"".as_bytes();
    timestamps(t, t.len(), "1709164800".as_bytes(), 10, 1709164800000, 1709164800000 + 90 * 86400000);
}

#[test(should_fail_with = "Timestamp before window")]
fn one_millisecond_outside_retention_rejects() {
    let t = "\"2024-02-29T00:00:00Z\"".as_bytes();
    timestamps(t, t.len(), "1709164800".as_bytes(), 10, 1709164800000, 1709164800001 + 90 * 86400000);
}

#[test(should_fail_with = "Timestamp after window")]
fn future_event_rejects() {
    let t = "\"2024-02-29T00:00:00Z\"".as_bytes();
    timestamps(t, t.len(), "1709164800".as_bytes(), 10, 1709164800000, 1709164799999);
}

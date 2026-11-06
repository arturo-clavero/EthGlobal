use crate::json;

// `len` must be the authenticated interval length; bytes after it are padding.
pub fn header_value<let N: u32>(bytes: [u8; N], len: u32) {
    assert((len > 0) & (len <= N), "Header value byte limit");
    for i in 0..N {
        if i < len {
            let c = bytes[i];
            assert(((c >= 32) & (c <= 126)) | (c == 9), "Invalid hidden header value");
        }
    }
}

// Exactly one complete JSON atom, including quotes for strings. The caller
// binds this kind and interval to authenticated public JSON structure.
// Kinds: 1 string, 2 number, 3 true, 4 false, 5 null.
pub fn json_atom<let N: u32>(bytes: [u8; N], len: u32) -> u8 {
    assert((len > 0) & (len <= N), "JSON atom byte limit");
    let first = bytes[0];
    let mut kind: u8 = 0;
    if first == 34 {
        kind = 1;
        let mut state = json::string_start();
        let mut closed = false;
        for i in 0..N {
            if (i > 0) & (i < len) {
                let (next, end) = json::string_byte(state, bytes[i]);
                state = next;
                if end {
                    assert(i + 1 == len, "Trailing bytes after JSON atom");
                    closed = true;
                }
            }
        }
        assert(closed, "Incomplete JSON string atom");
    } else if json::digit(first) | (first == 45) {
        kind = 2;
        let mut state = json::number_start(first);
        for i in 0..N {
            if (i > 0) & (i < len) { state = json::number_byte(state, bytes[i]); }
        }
        assert(json::number_end(state), "Incomplete JSON number");
    } else {
        assert((first == 116) | (first == 102) | (first == 110), "Unsupported JSON atom");
        kind = if first == 116 { 3 } else if first == 102 { 4 } else { 5 };
        let expected: [u8; 5] = if first == 116 { [116, 114, 117, 101, 0] }
            else if first == 102 { [102, 97, 108, 115, 101] }
            else { [110, 117, 108, 108, 0] };
        assert(len == if first == 102 { 5 } else { 4 }, "JSON literal atom length");
        for i in 0..5 {
            if i < len { assert(bytes[i] == expected[i], "Invalid JSON literal"); }
        }
    }
    kind
}

#[test]
fn accepts_header_ascii_and_tab() {
    let value = [32, 9, 33, 61, 92, 126, 255];
    header_value(value, 6);
}

#[test(should_fail_with = "Invalid hidden header value")]
fn rejects_header_crlf_injection() {
    let value = "token\r\nx-16signals-nonce: fake".as_bytes();
    header_value(value, value.len());
}

#[test(should_fail_with = "Invalid hidden header value")]
fn rejects_header_bare_lf() { header_value([65, 10, 66], 3); }

#[test(should_fail_with = "Invalid hidden header value")]
fn rejects_header_non_ascii() { header_value([65, 127], 2); }

#[test(should_fail_with = "Header value byte limit")]
fn rejects_empty_header() { header_value([65], 0); }

#[test(should_fail_with = "Header value byte limit")]
fn rejects_header_length_past_capacity() { header_value([65], 2); }

#[test]
fn accepts_atoms_and_authenticates_only_declared_prefix() {
    assert(json_atom([34, 34, 0], 2) == 1);
    assert(json_atom("-0.25e+12".as_bytes(), 9) == 2);
    assert(json_atom("0".as_bytes(), 1) == 2);
    assert(json_atom("true".as_bytes(), 4) == 3);
    assert(json_atom("false".as_bytes(), 5) == 4);
    assert(json_atom("null".as_bytes(), 4) == 5);
}

#[test]
fn accepts_escaped_quotes_and_unicode_escapes() {
    let value = "\"A \\\"quoted\\\" \\u540d \\/ \\\\ \\b\\f\\n\\r\\t\"".as_bytes();
    assert(json_atom(value, value.len()) == 1);
}

#[test]
fn accepts_raw_utf8_boundaries() {
    let value = [34, 194, 128, 223, 191, 224, 160, 128, 237, 159, 191,
        239, 191, 191, 240, 144, 128, 128, 244, 143, 191, 191, 34];
    assert(json_atom(value, value.len()) == 1);
}

#[test(should_fail_with = "Trailing bytes after JSON atom")]
fn rejects_comma_injection_after_string() {
    let value = "\"x\",\"status\":\"PERMISSION_DENIED\"".as_bytes();
    let _ = json_atom(value, value.len());
}

#[test(should_fail_with = "Trailing bytes after JSON atom")]
fn rejects_trailing_string_whitespace() { let _ = json_atom([34, 34, 32], 3); }

#[test(should_fail_with = "Unsupported JSON atom")]
fn rejects_leading_whitespace() { let _ = json_atom(" true".as_bytes(), 5); }

#[test(should_fail_with = "Unsupported JSON atom")]
fn rejects_object_container() { let _ = json_atom("{}".as_bytes(), 2); }

#[test(should_fail_with = "Unsupported JSON atom")]
fn rejects_array_container() { let _ = json_atom("[]".as_bytes(), 2); }

#[test(should_fail_with = "Incomplete JSON string atom")]
fn rejects_truncated_escape() { let _ = json_atom([34, 65, 92], 3); }

#[test(should_fail_with = "Invalid JSON Unicode escape")]
fn rejects_truncated_unicode_escape() { let _ = json_atom([34, 92, 117, 48, 48, 34], 6); }

#[test(should_fail_with = "Invalid JSON escape")]
fn rejects_unknown_escape() { let _ = json_atom([34, 92, 120, 34], 4); }

#[test(should_fail_with = "Unescaped JSON control byte")]
fn rejects_unescaped_control() { let _ = json_atom([34, 9, 34], 3); }

#[test(should_fail_with = "Invalid JSON UTF-8 lead")]
fn rejects_overlong_utf8() { let _ = json_atom([34, 192, 175, 34], 4); }

#[test(should_fail_with = "Invalid JSON UTF-8")]
fn rejects_utf8_surrogate() { let _ = json_atom([34, 237, 160, 128, 34], 5); }

#[test(should_fail_with = "Invalid JSON UTF-8")]
fn rejects_utf8_above_unicode_limit() { let _ = json_atom([34, 244, 144, 128, 128, 34], 6); }

#[test(should_fail_with = "Invalid JSON UTF-8")]
fn rejects_utf8_that_hides_closing_quote() { let _ = json_atom([34, 226, 34], 3); }

#[test(should_fail_with = "Leading zero in JSON number")]
fn rejects_leading_zero() { let _ = json_atom("01".as_bytes(), 2); }

#[test(should_fail_with = "Incomplete JSON number")]
fn rejects_incomplete_number_exponent() { let _ = json_atom("1e+".as_bytes(), 3); }

#[test(should_fail_with = "Incomplete JSON number")]
fn rejects_incomplete_number_fraction() { let _ = json_atom("1.".as_bytes(), 2); }

#[test(should_fail_with = "Invalid JSON number")]
fn rejects_number_comma_injection() { let _ = json_atom("1,true".as_bytes(), 6); }

#[test(should_fail_with = "Invalid JSON number")]
fn rejects_trailing_number_whitespace() { let _ = json_atom("1 ".as_bytes(), 2); }

#[test(should_fail_with = "JSON literal atom length")]
fn rejects_literal_trailing_bytes() { let _ = json_atom("true,false".as_bytes(), 10); }

#[test(should_fail_with = "Invalid JSON literal")]
fn rejects_malformed_literal() { let _ = json_atom("truX".as_bytes(), 4); }

#[test(should_fail_with = "JSON atom byte limit")]
fn rejects_atom_length_past_capacity() { let _ = json_atom([48], 2); }

#[test(should_fail_with = "JSON atom byte limit")]
fn rejects_empty_atom() { let _ = json_atom([48], 0); }

// Prove canonical outer-string escaping of one COMPLETE inner JSON atom. The
// interval excludes the outer string's quotes and includes the inner atom's quotes.
// shortcut: outer \/ and \u escapes are rejected, review other encodings if AWS emits them.
pub fn atom<let E: u32, let D: u32>(
    encoded: [u8; E], encoded_length: u32, decoded: [u8; D], decoded_length: u32,
) -> u8 {
    assert((encoded_length > 0) & (encoded_length <= E), "Encoded atom byte limit");
    let kind = gcp_private_json::atomic::json_atom(decoded, decoded_length);
    let mut at: u32 = 0;
    for i in 0..D {
        if i < decoded_length {
            let c = decoded[i];
            // A complete JSON atom has no raw controls; inner escapes remain bytes.
            assert(c >= 32, "Raw control in inner atom");
            if (c == 34) | (c == 92) {
                assert(at < encoded_length, "Truncated encoded atom");
                assert(encoded[at] == 92, "Noncanonical outer escape");
                at += 1;
            }
            assert(at < encoded_length, "Truncated encoded atom");
            assert(encoded[at] == c, "Escaped atom mismatch");
            at += 1;
        }
    }
    assert(at == encoded_length, "Trailing encoded bytes");
    kind
}

#[test]
fn accepts_string_quotes_backslash_and_inner_unicode_escape() {
    let decoded = [34, 92, 117, 48, 48, 54, 49, 92, 92, 92, 34, 34];
    let encoded = [92, 34, 92, 92, 117, 48, 48, 54, 49, 92, 92, 92, 92, 92, 92, 92, 34, 92, 34];
    assert(atom(encoded, encoded.len(), decoded, decoded.len()) == 1);
}

#[test]
fn accepts_raw_utf8_and_padding_outside_the_interval() {
    assert(atom([92, 34, 229, 144, 141, 92, 34, 255], 7, [34, 229, 144, 141, 34, 255], 5) == 1);
}

#[test]
fn accepts_scalar_types() {
    assert(atom("-1.2e+3".as_bytes(), 7, "-1.2e+3".as_bytes(), 7) == 2);
    assert(atom("true".as_bytes(), 4, "true".as_bytes(), 4) == 3);
    assert(atom("false".as_bytes(), 5, "false".as_bytes(), 5) == 4);
    assert(atom("null".as_bytes(), 4, "null".as_bytes(), 4) == 5);
}

#[test(should_fail_with = "Trailing bytes after JSON atom")]
fn rejects_sibling_injection() {
    let decoded = "\"x\",\"errorCode\":true".as_bytes();
    let _ = atom([0; 64], 64, decoded, decoded.len());
}

#[test(should_fail_with = "Unsupported JSON atom")]
fn rejects_hidden_container() {
    let _ = atom("{}".as_bytes(), 2, "{}".as_bytes(), 2);
}

#[test(should_fail_with = "Escaped atom mismatch")]
fn rejects_different_decoded_value() {
    let _ = atom([92, 34, 97, 92, 34], 5, [34, 98, 34], 3);
}

#[test(should_fail_with = "Noncanonical outer escape")]
fn rejects_unescaped_inner_quote() {
    let _ = atom([34, 97, 34], 3, [34, 97, 34], 3);
}

#[test(should_fail_with = "Escaped atom mismatch")]
fn rejects_outer_unicode_escape_alias() {
    let _ = atom([92, 117, 48, 48, 50, 50, 92, 34], 8, [34, 34], 2);
}

#[test(should_fail_with = "Escaped atom mismatch")]
fn rejects_outer_slash_escape_alias() {
    let _ = atom([92, 34, 92, 47, 92, 34], 6, [34, 47, 34], 3);
}

#[test(should_fail_with = "Truncated encoded atom")]
fn rejects_truncated_escape() {
    let _ = atom([92, 34, 92], 3, [34, 34], 2);
}

#[test(should_fail_with = "Trailing encoded bytes")]
fn rejects_trailing_outer_delimiter() {
    let _ = atom([92, 34, 92, 34, 44], 5, [34, 34], 2);
}

#[test(should_fail_with = "Invalid JSON UTF-8 lead")]
fn rejects_invalid_utf8() {
    let _ = atom([92, 34, 255, 92, 34], 5, [34, 255, 34], 3);
}

#[test(should_fail_with = "Encoded atom byte limit")]
fn rejects_encoded_length_past_capacity() {
    let _ = atom([92, 34, 92, 34], 5, [34, 34], 2);
}

#[test(should_fail_with = "Encoded atom byte limit")]
fn rejects_empty_interval() {
    let _ = atom([0], 0, [34, 34], 2);
}

#[test(should_fail_with = "JSON atom byte limit")]
fn rejects_decoded_length_past_capacity() {
    let _ = atom([92, 34, 92, 34], 4, [34, 34], 3);
}

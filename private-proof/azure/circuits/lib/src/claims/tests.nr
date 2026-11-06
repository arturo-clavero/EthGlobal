use super::{actor, transition, initial_bytes, encode, decode};

fn object_id() -> [u8; 36] { "aaaaaaaa-1111-2222-3333-444444444444".as_bytes() }
fn tenant() -> [u8; 36] { "bbbbbbbb-1111-2222-3333-444444444444".as_bytes() }

fn document<let N: u32>(extra: [u8; N]) -> [u8; 198 + N + 1] {
    let prefix = "{\"http://schemas.microsoft.com/identity/claims/objectidentifier\":\"aaaaaaaa-1111-2222-3333-444444444444\",\"http://schemas.microsoft.com/identity/claims/tenantid\":\"bbbbbbbb-1111-2222-3333-444444444444\"".as_bytes();
    let mut body = [0u8; 198 + N + 1];
    for i in 0..198 { body[i] = prefix[i]; }
    for i in 0..N { body[198 + i] = extra[i]; }
    body[198 + N] = 125;
    body
}

fn check<let N: u32>(body: [u8; N]) { actor(body, N, object_id(), tenant()); }

#[test]
fn accepts_flat_map_and_ignored_escaped_strings() {
    check(document(",\"metadata\":\"ignored \\\\ slash \\/ quote \\\" newline \\n unicode \\u0041\"".as_bytes()));
}

#[test]
fn accepts_whitespace_and_uppercase_source_uuid() {
    check(" \n{ \"http://schemas.microsoft.com/identity/claims/tenantid\" : \"BBBBBBBB-1111-2222-3333-444444444444\", \"http://schemas.microsoft.com/identity/claims/objectidentifier\" : \"AAAAAAAA-1111-2222-3333-444444444444\" } \t".as_bytes());
}

#[test]
fn accepts_valid_raw_utf8_in_ignored_value() {
    let body = document(",\"x\":\"ABCD\"".as_bytes());
    let mut changed = body; let at = 198 + 6;
    changed[at] = 240; changed[at + 1] = 159; changed[at + 2] = 152; changed[at + 3] = 128;
    check(changed);
}

#[test(should_fail_with = "Wrong Activity actor")]
fn rejects_wrong_actor_reference() {
    let body = document("".as_bytes()); actor(body, body.len(), tenant(), tenant());
}

#[test(should_fail_with = "Wrong Activity tenant")]
fn rejects_wrong_tenant_reference() {
    let body = document("".as_bytes()); actor(body, body.len(), object_id(), object_id());
}

#[test(should_fail_with = "Duplicate claims actor")]
fn rejects_duplicate_actor() {
    check(document(",\"http://schemas.microsoft.com/identity/claims/objectidentifier\":\"aaaaaaaa-1111-2222-3333-444444444444\"".as_bytes()));
}

#[test(should_fail_with = "Duplicate claims tenant")]
fn rejects_duplicate_tenant() {
    check(document(",\"http://schemas.microsoft.com/identity/claims/tenantid\":\"bbbbbbbb-1111-2222-3333-444444444444\"".as_bytes()));
}

#[test(should_fail_with = "Unsupported claims key")]
fn rejects_escaped_semantic_key() {
    check(document(",\"http:\\/\\/schemas.microsoft.com/identity/claims/tenantid\":\"bbbbbbbb-1111-2222-3333-444444444444\"".as_bytes()));
}

#[test(should_fail_with = "Invalid claims identity length")]
fn rejects_escaped_identity_value() {
    check("{\"http://schemas.microsoft.com/identity/claims/objectidentifier\":\"\\u0061aaaaaaa-1111-2222-3333-444444444444\",\"http://schemas.microsoft.com/identity/claims/tenantid\":\"bbbbbbbb-1111-2222-3333-444444444444\"}".as_bytes());
}

#[test(should_fail_with = "Expected claims key")]
fn rejects_trailing_comma() { check(document(",".as_bytes())); }

#[test(should_fail_with = "Trailing claims document")]
fn rejects_trailing_document() {
    let body = document("".as_bytes()); let mut appended = [0u8; 198 + 3];
    for i in 0..198 + 1 { appended[i] = body[i]; }
    appended[198 + 1] = 123; appended[198 + 2] = 125; check(appended);
}

#[test(should_fail_with = "Incomplete claims object")]
fn rejects_truncation() { let body = document("".as_bytes()); actor(body, body.len() - 1, object_id(), tenant()); }

#[test(should_fail_with = "Expected claims string")]
fn rejects_nested_object() { check(document(",\"metadata\":{}".as_bytes())); }

#[test(should_fail_with = "Expected claims string")]
fn rejects_non_string_scalar() { check(document(",\"metadata\":true".as_bytes())); }

#[test(should_fail_with = "Invalid JSON escape")]
fn rejects_invalid_ignored_escape() { check(document(",\"metadata\":\"\\q\"".as_bytes())); }

#[test(should_fail_with = "Invalid JSON Unicode escape")]
fn rejects_invalid_ignored_unicode_escape() { check(document(",\"metadata\":\"\\u00ZZ\"".as_bytes())); }

#[test(should_fail_with = "Unescaped JSON control byte")]
fn rejects_ignored_raw_control() {
    let mut body = document(",\"x\":\"ABCD\"".as_bytes()); body[198 + 6] = 10; check(body);
}

#[test(should_fail_with = "Invalid JSON UTF-8 lead")]
fn rejects_ignored_overlong_utf8_lead() {
    let mut body = document(",\"x\":\"ABCD\"".as_bytes()); body[198 + 6] = 192; check(body);
}

#[test(should_fail_with = "Invalid JSON UTF-8")]
fn rejects_ignored_bad_utf8_continuation() {
    let mut body = document(",\"x\":\"ABCD\"".as_bytes()); body[198 + 6] = 224; body[198 + 7] = 128; check(body);
}

#[test]
fn long_unknown_key_cannot_alias_selected_key() {
    check(document(",\"http://schemas.microsoft.com/identity/claims/objectidentifierXXXXXXXXXXXXXXXX\":\"not-an-identity\",\"http://schemas.microsoft.com/identity/claims/objectidentifieX\":\"also-not-an-identity\"".as_bytes()));
}

#[test(should_fail_with = "Missing claims identity")]
fn long_unknown_key_cannot_replace_actor() {
    check("{\"http://schemas.microsoft.com/identity/claims/objectidentifierXXXXXXXXXXXXXXXX\":\"aaaaaaaa-1111-2222-3333-444444444444\",\"http://schemas.microsoft.com/identity/claims/tenantid\":\"bbbbbbbb-1111-2222-3333-444444444444\"}".as_bytes());
}

#[test(should_fail_with = "Missing claims identity")]
fn rejects_empty_object() { check("{}".as_bytes()); }

#[test(should_fail_with = "Invalid claims reference")]
fn rejects_noncanonical_derived_reference() {
    let body = document("".as_bytes()); let mut id = object_id(); id[0] = 65; actor(body, body.len(), id, tenant());
}

#[test(should_fail_with = "Claims byte limit")]
fn rejects_length_past_capacity() {
    let body = document("".as_bytes()); actor(body, body.len() + 1, object_id(), tenant());
}

fn chunked<let N: u32>(body: [u8; N]) {
    let mut state = initial_bytes();
    for part in 0..(N + 31) / 32 {
        let offset = part * 32;
        let length = if N - offset < 32 { N - offset } else { 32 };
        let mut chunk = [0u8; 32];
        for i in 0..32 { if i < length { chunk[i] = body[offset + i]; } }
        state = transition(chunk, length, state, offset, N, object_id(), tenant());
        assert(encode(decode(state)) == state);
    }
}

#[test]
fn chunks_preserve_keys_values_and_escaped_ignored_strings() {
    chunked(document(",\"ignored\":\"some \\u0041 escaped \\\" metadata\"".as_bytes()));
}

#[test(should_fail_with = "Duplicate claims actor")]
fn chunks_reject_duplicate_actor_across_boundaries() {
    chunked(document(",\"http://schemas.microsoft.com/identity/claims/objectidentifier\":\"aaaaaaaa-1111-2222-3333-444444444444\"".as_bytes()));
}

#[test(should_fail_with = "Invalid claims state")]
fn state_rejects_noncanonical_boolean() { let mut state = initial_bytes(); state[68] = 2; let _ = decode(state); }

#[test(should_fail_with = "Invalid claims state count")]
fn state_rejects_oversized_counter() { let mut state = initial_bytes(); state[63] = 1; let _ = decode(state); }

#[test]
fn state_field_limb_encoding_is_exact_at_full_31_byte_bound() {
    let mut bytes = initial_bytes(); for i in 1..63 { bytes[i] = 255; }
    assert(encode(decode(bytes)) == bytes);
}

#[test(should_fail_with = "Claims initial state")]
fn chunks_reject_forged_initial_state() {
    let mut state = initial_bytes(); state[68] = 1;
    let _ = transition("{}".as_bytes(), 2, state, 0, 2, object_id(), tenant());
}

#[test(should_fail_with = "Claims state offset")]
fn chunks_reject_unanchored_continuation() {
    let _ = transition("{}".as_bytes(), 2, initial_bytes(), 2, 4, object_id(), tenant());
}

#[test(should_fail_with = "Claims chunk offset")]
fn chunks_reject_wrong_offset() {
    let _ = transition("{}".as_bytes(), 2, initial_bytes(), 1, 3, object_id(), tenant());
}

#[test(should_fail_with = "Claims chunk length")]
fn chunks_reject_short_interior_chunk() {
    let _ = transition("{}".as_bytes(), 1, initial_bytes(), 0, 3, object_id(), tenant());
}

#[test(should_fail_with = "Incomplete claims object")]
fn chunks_require_final_object_completion() {
    let _ = transition("{ ".as_bytes(), 2, initial_bytes(), 0, 2, object_id(), tenant());
}

#[test(should_fail_with = "Missing claims identity")]
fn chunks_require_final_identity_coverage() {
    let _ = transition("{}".as_bytes(), 2, initial_bytes(), 0, 2, object_id(), tenant());
}

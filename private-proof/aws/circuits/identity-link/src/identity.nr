fn word(c: u8) -> bool {
    ((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122)) | ((c >= 48) & (c <= 57)) | (c == 95)
}

// Canonical raw IAM XML fields. The first private profile rejects JSON-escaped ARN
// path characters rather than interpreting an XML/JSON spelling as another identity.
pub fn validate<let I: u32, let A: u32, let P: u32, let U: u32>(
    id: [u8; I], id_len: u32, arn: [u8; A], arn_len: u32,
    path: [u8; P], path_len: u32, user: [u8; U], user_len: u32,
) -> [u8; 12] {
    assert((id_len >= 16) & (id_len <= 128) & (id_len <= I), "Invalid IAM user ID length");
    assert((user_len > 0) & (user_len <= 64) & (user_len <= U), "Invalid IAM username length");
    assert((path_len > 0) & (path_len <= 512) & (path_len <= P), "Invalid IAM path length");
    assert((arn_len <= A) & (arn_len == 30 + path_len + user_len), "IAM ARN length mismatch");
    for i in 0..I { if i < id_len { assert(word(id[i]), "Invalid IAM user ID"); } }
    for i in 0..U {
        if i < user_len {
            let c = user[i];
            assert(word(c) | (c == 43) | (c == 61) | (c == 44) | (c == 46) | (c == 64) | (c == 45), "Invalid IAM username");
        }
    }
    assert((path[0] == 47) & (path[path_len - 1] == 47), "Invalid IAM path delimiters");
    for i in 0..P {
        if i < path_len {
            let c = path[i];
            assert((c >= 33) & (c <= 126) & (c != 34) & (c != 92) & (c != 38) & (c != 60) & (c != 62), "Unsupported IAM path byte");
        }
    }
    let prefix = "arn:aws:iam::".as_bytes();
    for i in 0..13 { assert(arn[i] == prefix[i], "Invalid IAM ARN prefix"); }
    let mut account = [0u8; 12];
    for i in 0..12 {
        let c = arn[13 + i];
        assert((c >= 48) & (c <= 57), "Invalid IAM account ID");
        account[i] = c;
    }
    let kind = ":user".as_bytes();
    for i in 0..5 { assert(arn[25 + i] == kind[i], "IAM ARN is not a user"); }
    for i in 0..P { if i < path_len { assert(arn[30 + i] == path[i], "IAM ARN path mismatch"); } }
    for i in 0..U { if i < user_len { assert(arn[30 + path_len + i] == user[i], "IAM ARN username mismatch"); } }
    account
}

#[test]
fn accepts_user_arn_and_extracts_only_its_account() {
    let arn = "arn:aws:iam::111122223333:user/team/alice".as_bytes();
    assert(validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/team/".as_bytes(), 6, "alice".as_bytes(), 5)
        == "111122223333".as_bytes());
}

#[test]
fn accepts_root_user_path_and_allowed_username_symbols() {
    let arn = "arn:aws:iam::111122223333:user/a+=,.@_-".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/".as_bytes(), 1, "a+=,.@_-".as_bytes(), 8);
}

#[test(should_fail_with = "Invalid IAM user ID")]
fn rejects_role_session_id() {
    let arn = "arn:aws:iam::111122223333:user/alice".as_bytes();
    let _ = validate("AROAEXAMPLE:session01".as_bytes(), 20, arn, arn.len(), "/".as_bytes(), 1, "alice".as_bytes(), 5);
}

#[test(should_fail_with = "IAM ARN is not a user")]
fn rejects_role_arn() {
    let arn = "arn:aws:iam::111122223333:role/alice".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/".as_bytes(), 1, "alice".as_bytes(), 5);
}

#[test(should_fail_with = "Invalid IAM account ID")]
fn rejects_account_lookalike() {
    let arn = "arn:aws:iam::11112222333X:user/alice".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/".as_bytes(), 1, "alice".as_bytes(), 5);
}

#[test(should_fail_with = "IAM ARN username mismatch")]
fn rejects_different_username() {
    let arn = "arn:aws:iam::111122223333:user/alice".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/".as_bytes(), 1, "other".as_bytes(), 5);
}

#[test(should_fail_with = "IAM ARN path mismatch")]
fn rejects_different_path() {
    let arn = "arn:aws:iam::111122223333:user/team/alice".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/else/".as_bytes(), 6, "alice".as_bytes(), 5);
}

#[test(should_fail_with = "Unsupported IAM path byte")]
fn rejects_escaped_arn_path_requirement() {
    let arn = "arn:aws:iam::111122223333:user/te\\m/alice".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/te\\m/".as_bytes(), 6, "alice".as_bytes(), 5);
}

#[test(should_fail_with = "Invalid IAM user ID length")]
fn rejects_short_immutable_id() {
    let arn = "arn:aws:iam::111122223333:user/alice".as_bytes();
    let _ = validate("short".as_bytes(), 5, arn, arn.len(), "/".as_bytes(), 1, "alice".as_bytes(), 5);
}

#[test(should_fail_with = "IAM ARN length mismatch")]
fn rejects_hidden_arn_suffix() {
    let arn = "arn:aws:iam::111122223333:user/alice/other".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/".as_bytes(), 1, "alice".as_bytes(), 5);
}

#[test(should_fail_with = "Invalid IAM user ID")]
fn identity_id_rejects_xml_entity_byte() {
    let arn = "arn:aws:iam::111122223333:user/alice".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC&1".as_bytes(), 21, arn, arn.len(), "/".as_bytes(), 1, "alice".as_bytes(), 5);
}

#[test(should_fail_with = "Invalid IAM username")]
fn identity_username_rejects_xml_markup() {
    let arn = "arn:aws:iam::111122223333:user/alic>".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/".as_bytes(), 1, "alic>".as_bytes(), 5);
}

#[test(should_fail_with = "Unsupported IAM path byte")]
fn identity_path_rejects_xml_normalization() {
    let arn = "arn:aws:iam::111122223333:user/\n/alice".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), "/\n/".as_bytes(), 3, "alice".as_bytes(), 5);
}

#[test(should_fail_with = "Unsupported IAM path byte")]
fn identity_path_rejects_non_ascii() {
    let arn = "arn:aws:iam::111122223333:user/x/alice".as_bytes();
    let _ = validate("AIDAEXAMPLESYNTHETIC01".as_bytes(), 21, arn, arn.len(), [47, 255, 47], 3, "alice".as_bytes(), 5);
}

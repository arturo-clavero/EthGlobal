use gcp_private_json::{commitment, json, scope};

fn raw_opening<let N: u32>(value: [u8; N], len: u32, blinder: [u8; 16], expected: [u8; 32]) {
    assert(len <= N, "Query field byte limit");
    let mut preimage = [0; N + 16];
    for i in 0..N { preimage[i] = value[i]; }
    for i in 0..16 { preimage[len + i] = blinder[i]; }
    let _: [u8; N] = commitment::authenticate(preimage, len, expected);
}

// The verifier binds these raw leaves to authenticated canonical query bodies
// and headers, including all fixed catalog predicates and cutoff/window values.
// This circuit joins every private insertion to the same identity scope.
fn main(
    nonce: pub [u8; 43],
    scope_hash: pub [u8; 32],
    group_count: pub u32,
    project_hashes: pub [[u8; 32]; 12],
    project_lengths: pub [u32; 12],
    email_hashes: pub [[u8; 32]; 6],
    email_lengths: pub [u32; 6],
    authuser_hash: pub [u8; 32],
    api_key_hash: pub [u8; 32],
    account: u8,
    email: [u8; 254],
    email_len: u32,
    id: [u8; 64],
    id_len: u32,
    project: [u8; 30],
    project_len: u32,
    salt: [u8; 32],
    project_blinders: [[u8; 16]; 12],
    email_blinders: [[u8; 16]; 6],
    authuser_blinder: [u8; 16],
    api_key: [u8; 39],
    api_key_blinder: [u8; 16],
) {
    assert((group_count >= 1) & (group_count <= 6), "Invalid query group count");
    let identity = json::Identity { email, email_len, id, id_len };
    json::validate_identity(identity);
    assert(scope::hash(nonce, salt, account, project, project_len, identity) == scope_hash, "Query scope mismatch");
    raw_opening([account + 48], 1, authuser_blinder, authuser_hash);

    let prefix = "AIza".as_bytes();
    for i in 0..4 { assert(api_key[i] == prefix[i], "Invalid Google API key prefix"); }
    for i in 4..39 {
        let c = api_key[i];
        assert(((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122)) |
            ((c >= 48) & (c <= 57)) | (c == 95) | (c == 45), "Invalid Google API key byte");
    }
    raw_opening(api_key, 39, api_key_blinder, api_key_hash);

    for i in 0..12 {
        if i < group_count * 2 {
            assert(project_lengths[i] == project_len, "Authenticated project length mismatch");
            raw_opening(project, project_len, project_blinders[i], project_hashes[i]);
        } else {
            assert((project_lengths[i] == 0) & (project_hashes[i] == [0; 32]), "Noncanonical inactive project leaf");
        }
    }
    for i in 0..6 {
        if i < group_count {
            assert(email_lengths[i] == email_len, "Authenticated query email length mismatch");
            raw_opening(email, email_len, email_blinders[i], email_hashes[i]);
        } else {
            assert((email_lengths[i] == 0) & (email_hashes[i] == [0; 32]), "Noncanonical inactive email leaf");
        }
    }
}

struct Fixture {
    nonce: [u8; 43], scope_hash: [u8; 32], group_count: u32,
    project_hashes: [[u8; 32]; 12], project_lengths: [u32; 12],
    email_hashes: [[u8; 32]; 6], email_lengths: [u32; 6],
    authuser_hash: [u8; 32], api_key_hash: [u8; 32],
    account: u8, email: [u8; 254], email_len: u32, id: [u8; 64], id_len: u32,
    project: [u8; 30], project_len: u32, salt: [u8; 32],
    project_blinders: [[u8; 16]; 12], email_blinders: [[u8; 16]; 6],
    authuser_blinder: [u8; 16], api_key: [u8; 39], api_key_blinder: [u8; 16],
}

fn fixture(groups: u32) -> Fixture {
    let mut email = [0; 254];
    let email_value = "user@example.invalid".as_bytes();
    for i in 0..20 { email[i] = email_value[i]; }
    let mut id = [0; 64];
    let id_value = "12345".as_bytes();
    for i in 0..5 { id[i] = id_value[i]; }
    let mut project = [0; 30];
    let project_value = "sample-project".as_bytes();
    for i in 0..14 { project[i] = project_value[i]; }
    let mut project_hashes = [[0; 32]; 12];
    let mut project_lengths = [0; 12];
    let mut email_hashes = [[0; 32]; 6];
    let mut email_lengths = [0; 6];
    // Independent hashlib digests of each raw private value || its blinder.
    for i in 0..12 {
        if i < groups * 2 {
            project_hashes[i] = [78, 211, 153, 246, 32, 127, 164, 177, 253, 173, 242, 246, 140, 201, 144, 248,
                213, 25, 229, 85, 56, 114, 12, 149, 198, 25, 237, 100, 175, 56, 130, 253];
            project_lengths[i] = 14;
        }
    }
    for i in 0..6 {
        if i < groups {
            email_hashes[i] = [215, 242, 68, 131, 152, 227, 214, 33, 210, 57, 46, 3, 187, 20, 245, 103,
                225, 25, 239, 244, 250, 35, 151, 170, 67, 29, 222, 146, 232, 224, 111, 140];
            email_lengths[i] = 20;
        }
    }
    let mut api_key = [65; 39];
    let prefix = "AIza".as_bytes();
    for i in 0..4 { api_key[i] = prefix[i]; }
    Fixture {
        nonce: [65; 43],
        scope_hash: [213, 120, 72, 20, 163, 135, 230, 24, 114, 55, 207, 84, 214, 158, 131, 72,
            61, 99, 133, 243, 19, 222, 218, 111, 241, 223, 4, 226, 38, 234, 182, 86],
        group_count: groups, project_hashes, project_lengths, email_hashes, email_lengths,
        authuser_hash: [126, 129, 38, 13, 8, 82, 24, 170, 103, 182, 52, 128, 153, 7, 179, 100,
            88, 57, 240, 226, 179, 173, 147, 172, 109, 146, 70, 250, 230, 242, 145, 234],
        api_key_hash: [244, 225, 204, 53, 245, 34, 177, 25, 254, 112, 115, 214, 30, 236, 9, 106,
            219, 163, 229, 103, 13, 40, 200, 61, 60, 109, 174, 145, 218, 199, 221, 155],
        account: 1, email, email_len: 20, id, id_len: 5, project, project_len: 14, salt: [7; 32],
        project_blinders: [[4; 16]; 12], email_blinders: [[5; 16]; 6], authuser_blinder: [1; 16],
        api_key, api_key_blinder: [6; 16],
    }
}

fn check(f: Fixture) {
    main(f.nonce, f.scope_hash, f.group_count, f.project_hashes, f.project_lengths, f.email_hashes,
        f.email_lengths, f.authuser_hash, f.api_key_hash, f.account, f.email, f.email_len, f.id,
        f.id_len, f.project, f.project_len, f.salt, f.project_blinders, f.email_blinders,
        f.authuser_blinder, f.api_key, f.api_key_blinder);
}

#[test]
fn two_queries_match_identity_scope_reference() { check(fixture(2)); }

#[test]
fn all_six_queries_bind_every_project_and_email_leaf() { check(fixture(6)); }

#[test(should_fail_with = "Invalid query group count")]
fn rejects_zero_queries() {
    let mut f = fixture(2); f.group_count = 0; check(f);
}

#[test(should_fail_with = "Invalid query group count")]
fn rejects_too_many_queries() {
    let mut f = fixture(2); f.group_count = 7; check(f);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_mismatched_project_in_last_query() {
    let mut f = fixture(6); f.project_hashes[11][0] = 0; check(f);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_mismatched_email_in_last_query() {
    let mut f = fixture(6); f.email_hashes[5][0] = 0; check(f);
}

#[test(should_fail_with = "Authenticated project length mismatch")]
fn rejects_project_length_mismatch() {
    let mut f = fixture(2); f.project_lengths[3] = 15; check(f);
}

#[test(should_fail_with = "Authenticated query email length mismatch")]
fn rejects_email_length_mismatch() {
    let mut f = fixture(2); f.email_lengths[1] = 21; check(f);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_mismatched_authenticated_account() {
    let mut f = fixture(2); f.authuser_hash[0] = 0; check(f);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_mismatched_authenticated_api_key() {
    let mut f = fixture(2); f.api_key_hash[0] = 0; check(f);
}

#[test(should_fail_with = "Invalid Google API key prefix")]
fn rejects_invalid_api_key_prefix() {
    let mut f = fixture(2); f.api_key[0] = 66; check(f);
}

#[test(should_fail_with = "Invalid Google API key byte")]
fn rejects_invalid_api_key_alphabet() {
    let mut f = fixture(2); f.api_key[38] = 43; check(f);
}

#[test(should_fail_with = "Noncanonical inactive project leaf")]
fn rejects_nonzero_inactive_project_hash() {
    let mut f = fixture(2); f.project_hashes[11][0] = 1; check(f);
}

#[test(should_fail_with = "Noncanonical inactive email leaf")]
fn rejects_nonzero_inactive_email_length() {
    let mut f = fixture(2); f.email_lengths[5] = 1; check(f);
}

#[test(should_fail_with = "Query scope mismatch")]
fn rejects_scope_from_another_challenge() {
    let mut f = fixture(2); f.nonce[0] = 66; check(f);
}

#[test(should_fail_with = "Query scope mismatch")]
fn rejects_private_project_outside_identity_scope() {
    let mut f = fixture(2); f.project[0] = 116; check(f);
}

#[test(should_fail_with = "Query scope mismatch")]
fn rejects_private_account_outside_identity_scope() {
    let mut f = fixture(2); f.account = 2; check(f);
}

#[test(should_fail_with = "Query scope mismatch")]
fn rejects_private_email_outside_identity_scope() {
    let mut f = fixture(2); f.email[0] = 118; check(f);
}

#[test(should_fail_with = "Invalid Google account ID")]
fn rejects_invalid_identity_syntax() {
    let mut f = fixture(2); f.id[0] = 65; check(f);
}

use gcp_private_json::{commitment, json, scope};

// Complete quoted leaves, with syntax enforced by validate_identity before use.
fn quoted_opening<let N: u32>(value: [u8; N], len: u32, blinder: [u8; 16], expected: [u8; 32]) {
    assert(len <= N, "Identity field byte limit");
    let mut preimage = [0; N + 18];
    preimage[0] = 34;
    for i in 0..N { preimage[i + 1] = value[i]; }
    preimage[len + 1] = 34;
    for i in 0..16 { preimage[len + 2 + i] = blinder[i]; }
    let _: [u8; N + 2] = commitment::authenticate(preimage, len + 2, expected);
}

// Public row facts and leaf commitments come from authenticated JSON structure.
// Private row selection is joined to the authenticated authuser request digit.
fn main(
    nonce: pub [u8; 43],
    scope_hash: pub [u8; 32],
    authuser_hash: pub [u8; 32],
    row_count: pub u32,
    row_email_hashes: pub [[u8; 32]; 10],
    row_id_hashes: pub [[u8; 32]; 10],
    row_email_lengths: pub [u32; 10],
    row_id_lengths: pub [u32; 10],
    row_valid: pub [bool; 10],
    account: u8,
    email: [u8; 254],
    email_len: u32,
    id: [u8; 64],
    id_len: u32,
    project: [u8; 30],
    project_len: u32,
    salt: [u8; 32],
    authuser_blinder: [u8; 16],
    email_blinder: [u8; 16],
    id_blinder: [u8; 16],
) {
    assert((row_count > 0) & (row_count <= 10), "Invalid Google account row count");
    assert((account as u32) < row_count, "Google account index out of range");
    for i in 0..10 {
        if i >= row_count {
            assert(!row_valid[i] & (row_email_lengths[i] == 0) & (row_id_lengths[i] == 0), "Noncanonical absent account row");
            assert((row_email_hashes[i] == [0; 32]) & (row_id_hashes[i] == [0; 32]), "Noncanonical absent account row");
        }
    }
    let selected = account as u32;
    assert(row_valid[selected], "Selected Google account is not valid");
    let identity = json::Identity { email, email_len, id, id_len };
    json::validate_identity(identity);
    assert(row_email_lengths[selected] == email_len + 2, "Authenticated email length mismatch");
    assert(row_id_lengths[selected] == id_len + 2, "Authenticated ID length mismatch");

    let mut authuser_preimage = [0; 17];
    authuser_preimage[0] = account + 48;
    for i in 0..16 { authuser_preimage[i + 1] = authuser_blinder[i]; }
    let _: [u8; 1] = commitment::authenticate(authuser_preimage, 1, authuser_hash);
    quoted_opening(email, email_len, email_blinder, row_email_hashes[selected]);
    quoted_opening(id, id_len, id_blinder, row_id_hashes[selected]);
    assert(scope::hash(nonce, salt, account, project, project_len, identity) == scope_hash, "Identity scope mismatch");
}

struct Fixture {
    nonce: [u8; 43], scope_hash: [u8; 32], authuser_hash: [u8; 32], row_count: u32,
    row_email_hashes: [[u8; 32]; 10], row_id_hashes: [[u8; 32]; 10],
    row_email_lengths: [u32; 10], row_id_lengths: [u32; 10], row_valid: [bool; 10],
    account: u8, email: [u8; 254], email_len: u32, id: [u8; 64], id_len: u32,
    project: [u8; 30], project_len: u32, salt: [u8; 32],
    authuser_blinder: [u8; 16], email_blinder: [u8; 16], id_blinder: [u8; 16],
}

fn fixture() -> Fixture {
    let mut email = [0; 254];
    let email_value = "user@example.invalid".as_bytes();
    for i in 0..20 { email[i] = email_value[i]; }
    let mut id = [0; 64];
    let id_value = "12345".as_bytes();
    for i in 0..5 { id[i] = id_value[i]; }
    let mut project = [0; 30];
    let project_value = "sample-project".as_bytes();
    for i in 0..14 { project[i] = project_value[i]; }
    let mut row_email_hashes = [[0; 32]; 10];
    let mut row_id_hashes = [[0; 32]; 10];
    // Independent Python hashlib vectors for quoted bytes || the stated blinder.
    row_email_hashes[1] = [63, 237, 215, 62, 20, 135, 17, 147, 149, 177, 218, 181, 204, 36, 16, 251,
        125, 93, 240, 61, 212, 139, 196, 117, 124, 87, 100, 238, 30, 89, 30, 168];
    row_id_hashes[1] = [177, 173, 213, 180, 211, 67, 239, 172, 248, 214, 132, 213, 175, 140, 185, 245,
        116, 199, 115, 75, 95, 242, 65, 92, 25, 33, 223, 116, 96, 207, 169, 52];
    let mut row_email_lengths = [0; 10];
    let mut row_id_lengths = [0; 10];
    let mut row_valid = [false; 10];
    row_email_lengths[1] = 22;
    row_id_lengths[1] = 7;
    row_valid[1] = true;
    Fixture {
        nonce: [65; 43],
        scope_hash: [213, 120, 72, 20, 163, 135, 230, 24, 114, 55, 207, 84, 214, 158, 131, 72,
            61, 99, 133, 243, 19, 222, 218, 111, 241, 223, 4, 226, 38, 234, 182, 86],
        authuser_hash: [126, 129, 38, 13, 8, 82, 24, 170, 103, 182, 52, 128, 153, 7, 179, 100,
            88, 57, 240, 226, 179, 173, 147, 172, 109, 146, 70, 250, 230, 242, 145, 234],
        row_count: 2, row_email_hashes, row_id_hashes, row_email_lengths, row_id_lengths, row_valid,
        account: 1, email, email_len: 20, id, id_len: 5, project, project_len: 14, salt: [7; 32],
        authuser_blinder: [1; 16], email_blinder: [2; 16], id_blinder: [3; 16],
    }
}

fn check(f: Fixture) {
    main(f.nonce, f.scope_hash, f.authuser_hash, f.row_count, f.row_email_hashes, f.row_id_hashes,
        f.row_email_lengths, f.row_id_lengths, f.row_valid, f.account, f.email, f.email_len, f.id,
        f.id_len, f.project, f.project_len, f.salt, f.authuser_blinder, f.email_blinder, f.id_blinder);
}

#[test]
fn selects_private_second_row_and_matches_reference_scope() { check(fixture()); }

#[test(should_fail_with = "Google account index out of range")]
fn rejects_selection_outside_authenticated_rows() {
    let mut f = fixture(); f.account = 2; check(f);
}

#[test(should_fail_with = "Selected Google account is not valid")]
fn rejects_unsigned_or_unverified_selected_row() {
    let mut f = fixture(); f.row_valid[1] = false; check(f);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_different_authenticated_authuser() {
    let mut f = fixture(); f.authuser_hash[0] = 0; check(f);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_different_authenticated_email() {
    let mut f = fixture(); f.row_email_hashes[1][0] = 0; check(f);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_different_authenticated_id() {
    let mut f = fixture(); f.row_id_hashes[1][0] = 0; check(f);
}

#[test(should_fail_with = "Authenticated email length mismatch")]
fn rejects_different_authenticated_email_length() {
    let mut f = fixture(); f.row_email_lengths[1] = 23; check(f);
}

#[test(should_fail_with = "Authenticated ID length mismatch")]
fn rejects_different_authenticated_id_length() {
    let mut f = fixture(); f.row_id_lengths[1] = 8; check(f);
}

#[test(should_fail_with = "Noncanonical absent account row")]
fn rejects_hidden_row_beyond_row_count() {
    let mut f = fixture(); f.row_email_hashes[9][0] = 1; check(f);
}

#[test(should_fail_with = "Identity scope mismatch")]
fn rejects_scope_from_another_challenge() {
    let mut f = fixture(); f.nonce[0] = 66; check(f);
}

#[test(should_fail_with = "Identity scope mismatch")]
fn rejects_scope_from_another_project() {
    let mut f = fixture(); f.project[0] = 116; check(f);
}

#[test(should_fail_with = "Noncanonical scope padding")]
fn rejects_noncanonical_private_padding() {
    let mut f = fixture(); f.email[253] = 1; check(f);
}

#[test(should_fail_with = "Service account is not a Google user")]
fn rejects_service_account_identity() {
    let mut f = fixture();
    f.email = [0; 254];
    let email = "user@project.iam.gserviceaccount.com".as_bytes();
    for i in 0..email.len() { f.email[i] = email[i]; }
    f.email_len = email.len();
    check(f);
}

#[test(should_fail_with = "Invalid Google account ID")]
fn rejects_nonnumeric_identity() {
    let mut f = fixture(); f.id[0] = 65; check(f);
}

#[test(should_fail_with = "Invalid Google email local part")]
fn rejects_email_quote_injection() {
    let mut f = fixture(); f.email[0] = 34; check(f);
}

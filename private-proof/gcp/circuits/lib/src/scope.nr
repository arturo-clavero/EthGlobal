use crate::json::Identity;

fn lower(c: u8) -> bool { (c >= 97) & (c <= 122) }
fn digit(c: u8) -> bool { (c >= 48) & (c <= 57) }

fn padding<let N: u32>(bytes: [u8; N], length: u32) {
    assert(length <= N, "Scope field byte limit");
    for i in 0..N {
        if i >= length { assert(bytes[i] == 0, "Noncanonical scope padding"); }
    }
}

// Fixed 447-byte encoding; every length occupies exactly one byte:
// domain20 | nonce43 | salt32 | account1 | project_len1 | project30 |
// email_len1 | email254 | id_len1 | id64.
// The caller samples salt privately. Identity comes from authenticated extraction.
pub fn hash(
    nonce: [u8; 43], salt: [u8; 32], account: u8,
    project: [u8; 30], project_len: u32, identity: Identity,
) -> [u8; 32] {
    assert(account < 10, "Invalid Google account selector");
    assert((project_len >= 6) & (project_len <= 30), "Invalid GCP project length");
    assert((identity.email_len > 0) & (identity.email_len <= 254), "Invalid scope email length");
    assert((identity.id_len > 0) & (identity.id_len <= 64), "Invalid scope identity length");
    padding(project, project_len);
    padding(identity.email, identity.email_len);
    padding(identity.id, identity.id_len);
    // Existing contract: ^[a-z][a-z0-9-]{4,28}[a-z0-9]$.
    assert(lower(project[0]), "Invalid GCP project prefix");
    assert(lower(project[project_len - 1]) | digit(project[project_len - 1]), "Invalid GCP project suffix");
    for i in 0..30 {
        if i < project_len {
            assert(lower(project[i]) | digit(project[i]) | (project[i] == 45), "Invalid GCP project byte");
        }
    }
    let mut encoded = [0u8; 447];
    let domain = "gcp-private-scope-v1".as_bytes();
    for i in 0..20 { encoded[i] = domain[i]; }
    for i in 0..43 { encoded[20 + i] = nonce[i]; }
    for i in 0..32 { encoded[63 + i] = salt[i]; }
    encoded[95] = account;
    encoded[96] = project_len as u8;
    for i in 0..30 { encoded[97 + i] = project[i]; }
    encoded[127] = identity.email_len as u8;
    for i in 0..254 { encoded[128 + i] = identity.email[i]; }
    encoded[382] = identity.id_len as u8;
    for i in 0..64 { encoded[383 + i] = identity.id[i]; }
    sha256::sha256_var(encoded, 447)
}

fn sample_identity() -> Identity {
    let mut email = [0u8; 254];
    let value = "user@example.invalid".as_bytes();
    for i in 0..20 { email[i] = value[i]; }
    let mut id = [0u8; 64];
    let value = "12345".as_bytes();
    for i in 0..5 { id[i] = value[i]; }
    Identity { email, email_len: 20, id, id_len: 5 }
}

fn sample_project() -> [u8; 30] {
    let mut project = [0u8; 30];
    let value = "sample-project".as_bytes();
    for i in 0..14 { project[i] = value[i]; }
    project
}

// Independent Python hashlib vector pins the complete fixed-width encoding.
#[test]
fn fixed_scope_encoding_matches_reference_digest() {
    assert(hash([65u8; 43], [7u8; 32], 0, sample_project(), 14, sample_identity()) == [0, 23, 155, 68, 194, 136, 173, 248, 122, 163, 205, 141, 26, 80, 242, 182, 77, 57, 66, 149, 36, 110, 230, 80, 125, 64, 64, 221, 41, 116, 13, 41]);
}

#[test]
fn nonce_and_salt_are_bound_into_scope() {
    let expected = [0, 23, 155, 68, 194, 136, 173, 248, 122, 163, 205, 141, 26, 80, 242, 182, 77, 57, 66, 149, 36, 110, 230, 80, 125, 64, 64, 221, 41, 116, 13, 41];
    assert(hash([66u8; 43], [7u8; 32], 0, sample_project(), 14, sample_identity()) != expected);
    assert(hash([65u8; 43], [8u8; 32], 0, sample_project(), 14, sample_identity()) != expected);
}

#[test(should_fail_with = "Noncanonical scope padding")]
fn project_padding_cannot_change_the_committed_scope() {
    let mut project = sample_project();
    project[29] = 120;
    let _ = hash([65u8; 43], [7u8; 32], 0, project, 14, sample_identity());
}

#[test(should_fail_with = "Noncanonical scope padding")]
fn identity_padding_cannot_change_the_committed_scope() {
    let mut identity = sample_identity();
    identity.email[253] = 120;
    let _ = hash([65u8; 43], [7u8; 32], 0, sample_project(), 14, identity);
}

#[test(should_fail_with = "Invalid GCP project prefix")]
fn project_prefix_matches_existing_contract() {
    let mut project = sample_project();
    project[0] = 45;
    let _ = hash([65u8; 43], [7u8; 32], 0, project, 14, sample_identity());
}

#[test(should_fail_with = "Invalid GCP project suffix")]
fn project_suffix_matches_existing_contract() {
    let mut project = sample_project();
    project[13] = 45;
    let _ = hash([65u8; 43], [7u8; 32], 0, project, 14, sample_identity());
}

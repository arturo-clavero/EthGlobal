use super::{actor_uuid, main};

fn fixture() -> ([u8; 32], [u8; 32], [u8; 32], [u8; 54], [u8; 32]) {
    let quoted = "\"abcdef01-2345-6789-abcd-ef0123456789\"".as_bytes();
    let mut opening = [0u8; 54];
    for i in 0..38 { opening[i] = quoted[i]; }
    for i in 0..16 { opening[38 + i] = (i + 1) as u8; }
    let challenge = [17u8; 32];
    let salt = [23u8; 32];
    // Literal offsets independently pin the existing identity-v1 format.
    let mut binding_input = [0u8; 117];
    let domain = "azure-identity-v1".as_bytes();
    for i in 0..17 { binding_input[i] = domain[i]; }
    for i in 0..32 { binding_input[17 + i] = challenge[i]; binding_input[49 + i] = salt[i]; }
    for i in 0..36 { binding_input[81 + i] = quoted[i + 1]; }
    (sha256::sha256_var(opening, 54), challenge,
        sha256::sha256_var(binding_input, 117), opening, salt)
}

#[test]
fn accepts_private_graph_actor_bridge() {
    let (hash, challenge, binding, opening, salt) = fixture();
    // Independent Python hashlib vector pins the exact existing domain and byte order.
    assert(binding == [14, 53, 76, 128, 71, 252, 210, 78, 130, 155, 44, 208, 191, 29, 136, 6,
        70, 173, 113, 164, 179, 160, 17, 117, 182, 51, 151, 133, 154, 214, 46, 96]);
    main(hash, challenge, binding, opening, salt);
}

#[test(should_fail)]
fn rejects_wrong_opening() {
    let (hash, challenge, binding, mut opening, salt) = fixture();
    opening[53] = opening[53] + 1;
    main(hash, challenge, binding, opening, salt);
}

#[test(should_fail_with = "Identity challenge binding mismatch")]
fn rejects_authenticated_different_actor() {
    let (_, challenge, binding, mut opening, salt) = fixture();
    opening[1] = 98;
    main(sha256::sha256_var(opening, 54), challenge, binding, opening, salt);
}

#[test(should_fail_with = "Identity challenge binding mismatch")]
fn rejects_wrong_challenge() {
    let (hash, mut challenge, binding, opening, salt) = fixture();
    challenge[0] = 18;
    main(hash, challenge, binding, opening, salt);
}

#[test(should_fail_with = "Identity challenge binding mismatch")]
fn rejects_wrong_salt() {
    let (hash, challenge, binding, opening, mut salt) = fixture();
    salt[0] = 24;
    main(hash, challenge, binding, opening, salt);
}

#[test(should_fail_with = "Identity challenge binding mismatch")]
fn rejects_wrong_binding() {
    let (hash, challenge, mut binding, opening, salt) = fixture();
    binding[0] = binding[0] ^ 1;
    main(hash, challenge, binding, opening, salt);
}

#[test(should_fail_with = "Invalid canonical Graph actor")]
fn rejects_uppercase_actor() {
    let mut quoted = "\"abcdef01-2345-6789-abcd-ef0123456789\"".as_bytes();
    quoted[1] = 65;
    let _ = actor_uuid(quoted);
}

#[test(should_fail_with = "Invalid canonical Graph actor")]
fn rejects_malformed_uuid() {
    let mut quoted = "\"abcdef01-2345-6789-abcd-ef0123456789\"".as_bytes();
    quoted[9] = 48;
    let _ = actor_uuid(quoted);
}

#[test(should_fail_with = "Expected quoted Graph actor")]
fn rejects_unquoted_actor() {
    let mut quoted = "\"abcdef01-2345-6789-abcd-ef0123456789\"".as_bytes();
    quoted[37] = 32;
    let _ = actor_uuid(quoted);
}

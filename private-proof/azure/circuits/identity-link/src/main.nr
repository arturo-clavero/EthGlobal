mod tests;

fn actor_uuid(quoted: [u8; 38]) -> [u8; 36] {
    assert((quoted[0] == 34) & (quoted[37] == 34), "Expected quoted Graph actor");
    let mut actor = [0u8; 36];
    for i in 0..36 {
        let c = quoted[i + 1];
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) {
            assert(c == 45, "Invalid canonical Graph actor");
        } else {
            assert(((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)), "Invalid canonical Graph actor");
        }
        actor[i] = c;
    }
    actor
}

// The verifier must first authenticate identity_binding through the existing Graph
// identity proof for this same challenge. actor_hash is derived, never a native range.
fn main(
    actor_hash: pub [u8; 32],
    challenge: pub [u8; 32],
    identity_binding: pub [u8; 32],
    actor_preimage: [u8; 54],
    salt: [u8; 32],
) {
    let actor = actor_uuid(source::commitment::authenticate::<38>(actor_preimage, 38, actor_hash));
    // Keep this byte-for-byte identical to identity/src/main.nr's binding format.
    let domain = "azure-identity-v1".as_bytes();
    let mut input = [0u8; 117];
    for i in 0..domain.len() { input[i] = domain[i]; }
    for i in 0..32 {
        input[domain.len() + i] = challenge[i];
        input[domain.len() + 32 + i] = salt[i];
    }
    for i in 0..36 { input[domain.len() + 64 + i] = actor[i]; }
    assert(sha256::sha256_var(input, input.len()) == identity_binding, "Identity challenge binding mismatch");
}

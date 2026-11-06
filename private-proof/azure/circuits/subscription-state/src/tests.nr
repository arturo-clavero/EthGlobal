use super::main;

fn fixture(state: [u8; 9]) -> ([u8; 32], [u8; 25]) {
    let mut preimage = [0u8; 25];
    for i in 0..9 { preimage[i] = state[i]; }
    for i in 9..25 { preimage[i] = i as u8; }
    (sha256::sha256_var(preimage, 25), preimage)
}

#[test]
fn proves_enabled_subscription() {
    let (hash, preimage) = fixture("\"Enabled\"".as_bytes());
    main(hash, preimage);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_wrong_opening() {
    let (hash, mut preimage) = fixture("\"Enabled\"".as_bytes());
    preimage[9] = preimage[9] ^ 1;
    main(hash, preimage);
}

#[test(should_fail_with = "Subscription must be enabled")]
fn rejects_authenticated_other_state() {
    let (hash, preimage) = fixture("\"Revoked\"".as_bytes());
    main(hash, preimage);
}

#[test(should_fail_with = "Subscription must be enabled")]
fn rejects_authenticated_quote_injection() {
    let (hash, preimage) = fixture("\"Enabled,".as_bytes());
    main(hash, preimage);
}

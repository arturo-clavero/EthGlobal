use super::main;

fn fixture() -> ([[u8; 32]; 2], [u8; 52], [u8; 54]) {
    let raw = "aBcDeFaB-1111-2222-3333-444444444444".as_bytes();
    let quoted = "\"AbCdEfAb-1111-2222-3333-444444444444\"".as_bytes();
    let mut request = [0u8; 52];
    let mut reference = [0u8; 54];
    for i in 0..36 { request[i] = raw[i]; }
    for i in 0..38 { reference[i] = quoted[i]; }
    for i in 0..16 { request[36 + i] = (i + 1) as u8; reference[38 + i] = (i + 32) as u8; }
    ([sha256::sha256_var(request, 52), sha256::sha256_var(reference, 54)], request, reference)
}

#[test]
fn matches_independently_blinded_mixed_case_ids() {
    let (hashes, request, reference) = fixture();
    assert(hashes[0] != hashes[1]);
    main(hashes, request, reference);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_wrong_request_opening() {
    let (hashes, mut request, reference) = fixture();
    request[36] = request[36] ^ 1;
    main(hashes, request, reference);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_wrong_reference_opening() {
    let (hashes, request, mut reference) = fixture();
    reference[38] = reference[38] ^ 1;
    main(hashes, request, reference);
}

#[test(should_fail_with = "Request UUID scope mismatch")]
fn rejects_authenticated_other_scope() {
    let (mut hashes, mut request, reference) = fixture();
    request[35] = 53;
    hashes[0] = sha256::sha256_var(request, 52);
    main(hashes, request, reference);
}

#[test(should_fail_with = "Invalid request UUID")]
fn rejects_authenticated_separator_injection() {
    let (mut hashes, mut request, reference) = fixture();
    request[8] = 47;
    hashes[0] = sha256::sha256_var(request, 52);
    main(hashes, request, reference);
}

#[test(should_fail_with = "Invalid request UUID")]
fn rejects_authenticated_non_hex_reference() {
    let (mut hashes, request, mut reference) = fixture();
    reference[1] = 71;
    hashes[1] = sha256::sha256_var(reference, 54);
    main(hashes, request, reference);
}

#[test(should_fail_with = "Expected quoted UUID reference")]
fn rejects_authenticated_reference_quote_injection() {
    let (mut hashes, request, mut reference) = fixture();
    reference[37] = 44;
    hashes[1] = sha256::sha256_var(reference, 54);
    main(hashes, request, reference);
}

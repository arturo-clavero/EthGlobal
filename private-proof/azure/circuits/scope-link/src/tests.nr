use super::main;

fn fixture() -> ([[u8; 32]; 6], [[u8; 54]; 6]) {
    let values = [
        "\"aaaaaaaa-1111-2222-3333-444444444444\"".as_bytes(),
        "\"AAAAAAAA-1111-2222-3333-444444444444\"".as_bytes(),
        "\"bbbbbbbb-1111-2222-3333-444444444444\"".as_bytes(),
        "\"BBBBBBBB-1111-2222-3333-444444444444\"".as_bytes(),
        "\"cccccccc-1111-2222-3333-444444444444\"".as_bytes(),
        "\"CCCCCCCC-1111-2222-3333-444444444444\"".as_bytes(),
    ];
    let mut preimages = [[0u8; 54]; 6];
    let mut hashes = [[0u8; 32]; 6];
    for i in 0..6 {
        for j in 0..38 { preimages[i][j] = values[i][j]; }
        for j in 38..54 { preimages[i][j] = (i * 16 + j) as u8; }
        hashes[i] = sha256::sha256_var(preimages[i], 54);
    }
    (hashes, preimages)
}

#[test]
fn matches_independently_blinded_case_insensitive_ids() {
    let (hashes, preimages) = fixture();
    assert(hashes[0] != hashes[1]);
    main(hashes, preimages);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_wrong_opening() {
    let (hashes, mut preimages) = fixture();
    preimages[0][38] = preimages[0][38] ^ 1;
    main(hashes, preimages);
}

#[test(should_fail_with = "Wrong Activity actor")]
fn rejects_authenticated_other_actor() {
    let (mut hashes, preimages) = fixture();
    hashes[1] = hashes[2];
    let mut swapped = preimages;
    swapped[1] = preimages[2];
    main(hashes, swapped);
}

#[test(should_fail_with = "Wrong Activity tenant")]
fn rejects_authenticated_other_tenant() {
    let (mut hashes, mut preimages) = fixture();
    hashes[3] = hashes[4]; preimages[3] = preimages[4];
    main(hashes, preimages);
}

#[test(should_fail_with = "Wrong Activity subscription")]
fn rejects_authenticated_other_subscription() {
    let (mut hashes, mut preimages) = fixture();
    hashes[5] = hashes[0]; preimages[5] = preimages[0];
    main(hashes, preimages);
}

#[test(should_fail_with = "Invalid Azure UUID")]
fn rejects_authenticated_non_hex_id() {
    let (mut hashes, mut preimages) = fixture();
    preimages[0][1] = 103;
    hashes[0] = sha256::sha256_var(preimages[0], 54);
    main(hashes, preimages);
}

#[test(should_fail_with = "Expected quoted Azure UUID")]
fn rejects_authenticated_syntax_injection() {
    let (mut hashes, mut preimages) = fixture();
    preimages[0][37] = 44;
    hashes[0] = sha256::sha256_var(preimages[0], 54);
    main(hashes, preimages);
}

use super::main;

fn fixture<let K: u32, let O: u32>(key: [u8; K], object: [u8; O]) -> ([[u8; 32]; 2], [u32; 2], [u8; 80], [u8; 144]) {
    let mut key_preimage = [0u8; 80]; let mut object_preimage = [0u8; 144];
    for i in 0..K { key_preimage[i] = key[i]; }
    for i in 0..O { object_preimage[i] = object[i]; }
    for i in 0..16 { key_preimage[K + i] = 9; object_preimage[O + i] = 17; }
    ([sha256::sha256_var(key_preimage, K + 16), sha256::sha256_var(object_preimage, O + 16)], [K, O], key_preimage, object_preimage)
}

#[test]
fn accepts_private_metadata_without_disclosing_inner_schema() {
    let (hashes, lengths, key, object) = fixture("\"privateTag\"".as_bytes(), "{\"category\":\"private\",\"privateLabel\":\"secret\"}".as_bytes());
    main(hashes, lengths, key, object);
}

#[test]
fn empty_object_is_valid_ignored_metadata() {
    let (hashes, lengths, key, object) = fixture("\"privateTag\"".as_bytes(), "{}".as_bytes());
    main(hashes, lengths, key, object);
}

#[test(should_fail_with = "Invalid private tenant key length")]
fn rejects_empty_key() {
    let (hashes, lengths, key, object) = fixture("\"\"".as_bytes(), "{}".as_bytes());
    main(hashes, lengths, key, object);
}

#[test(should_fail_with = "Private tenant key shadows a reserved field")]
fn rejects_reserved_scope_key() {
    let (hashes, lengths, key, object) = fixture("\"subscriptionId\"".as_bytes(), "{}".as_bytes());
    main(hashes, lengths, key, object);
}

#[test(should_fail_with = "Noncanonical private tenant key")]
fn rejects_escaped_reserved_key() {
    let (hashes, lengths, key, object) = fixture("\"sta\\u0074e\"".as_bytes(), "{}".as_bytes());
    main(hashes, lengths, key, object);
}

#[test(should_fail_with = "Expected private tenant metadata object")]
fn rejects_array_instead_of_object() {
    let (hashes, lengths, key, object) = fixture("\"privateTag\"".as_bytes(), "[]".as_bytes());
    main(hashes, lengths, key, object);
}

#[test(should_fail)]
fn rejects_malformed_object() {
    let (hashes, lengths, key, object) = fixture("\"privateTag\"".as_bytes(), "{\"x\":1,}".as_bytes());
    main(hashes, lengths, key, object);
}

#[test(should_fail_with = "Transcript byte limit")]
fn rejects_oversize_key() {
    let (hashes, mut lengths, key, object) = fixture("\"privateTag\"".as_bytes(), "{}".as_bytes());
    lengths[0] = 65;
    main(hashes, lengths, key, object);
}

#[test(should_fail_with = "Transcript byte limit")]
fn rejects_oversize_object() {
    let (hashes, mut lengths, key, object) = fixture("\"privateTag\"".as_bytes(), "{}".as_bytes());
    lengths[1] = 129;
    main(hashes, lengths, key, object);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_wrong_key_opening() {
    let (hashes, lengths, mut key, object) = fixture("\"privateTag\"".as_bytes(), "{}".as_bytes());
    key[lengths[0]] = key[lengths[0]] ^ 1;
    main(hashes, lengths, key, object);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_wrong_object_opening() {
    let (hashes, lengths, key, mut object) = fixture("\"privateTag\"".as_bytes(), "{}".as_bytes());
    object[lengths[1]] = object[lengths[1]] ^ 1;
    main(hashes, lengths, key, object);
}

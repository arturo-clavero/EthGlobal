use gcp_private_json::{commitment, json};

// The verifier derives slot ordering, absence and these commitments from
// authenticated response structure. This circuit proves only timestamp dates.
fn main(
    hashes: pub [[u8; 32]; 6],
    lengths: pub [u32; 6],
    cutoff: pub u64,
    window: pub u32,
    preimages: [[u8; 64]; 6],
) {
    json::validate_time_window(cutoff, window);
    // Catalog canonical queries use a four-digit ISO year.
    assert(cutoff <= 253402300799999, "Invalid batch cutoff");
    for i in 0..6 {
        if lengths[i] == 0 {
            assert(hashes[i] == [0; 32], "Absent timestamp must have zero hash");
        } else {
            let bytes: [u8; 48] = commitment::authenticate(preimages[i], lengths[i], hashes[i]);
            json::timestamp_atom(bytes, lengths[i], cutoff, window);
        }
    }
}

fn opening<let N: u32>(value: [u8; N]) -> [u8; 64] {
    let mut bytes = [0; 64];
    for i in 0..N { bytes[i] = value[i]; }
    for i in 0..16 { bytes[N + i] = i as u8; }
    bytes
}

#[test]
fn all_absent_slots_accept_valid_public_window() {
    main([[0; 32]; 6], [0; 6], 1704067200000, 7, [[0; 64]; 6]);
}

#[test(should_fail_with = "Absent timestamp must have zero hash")]
fn absent_slot_cannot_carry_a_hash() {
    let mut hashes = [[0; 32]; 6];
    hashes[5][31] = 1;
    main(hashes, [0; 6], 1704067200000, 7, [[0; 64]; 6]);
}

#[test(should_fail_with = "Invalid time window")]
fn all_absent_slots_still_validate_window() {
    main([[0; 32]; 6], [0; 6], 1704067200000, 0, [[0; 64]; 6]);
}

#[test(should_fail_with = "Invalid cutoff")]
fn all_absent_slots_still_validate_cutoff() {
    main([[0; 32]; 6], [0; 6], 8640000000000001, 7, [[0; 64]; 6]);
}

#[test(should_fail_with = "Invalid batch cutoff")]
fn all_absent_slots_still_validate_catalog_cutoff() {
    main([[0; 32]; 6], [0; 6], 253402300800000, 7, [[0; 64]; 6]);
}

#[test]
fn observed_timestamps_mix_with_absent_slots() {
    // Independent hashlib reference: quoted timestamp || bytes(0..16).
    let digest = [178, 226, 190, 169, 1, 228, 88, 45, 96, 89, 70, 161, 1, 204, 53, 226,
        184, 180, 77, 5, 18, 181, 168, 106, 239, 26, 5, 76, 213, 212, 149, 8];
    let value = opening("\"2023-12-31T12:00:00Z\"".as_bytes());
    let mut hashes = [[0; 32]; 6];
    let mut lengths = [0; 6];
    let mut preimages = [[0; 64]; 6];
    hashes[0] = digest;
    lengths[0] = 22;
    preimages[0] = value;
    hashes[5] = digest;
    lengths[5] = 22;
    preimages[5] = value;
    main(hashes, lengths, 1704067200000, 7, preimages);
}

#[test(should_fail_with = "Timestamp after window")]
fn authentic_timestamp_one_nanosecond_after_window_is_rejected() {
    let digest = [120, 250, 82, 175, 159, 4, 104, 222, 144, 91, 176, 223, 17, 53, 231, 228,
        53, 9, 242, 28, 194, 61, 87, 200, 2, 24, 255, 176, 41, 235, 226, 60];
    let value = opening("\"2024-01-01T00:00:00.000000001Z\"".as_bytes());
    let mut hashes = [[0; 32]; 6];
    let mut lengths = [0; 6];
    let mut preimages = [[0; 64]; 6];
    hashes[0] = digest;
    lengths[0] = 32;
    preimages[0] = value;
    main(hashes, lengths, 1704067200000, 7, preimages);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn valid_timestamp_cannot_use_another_authenticated_hash() {
    let mut lengths = [0; 6];
    let mut preimages = [[0; 64]; 6];
    lengths[0] = 22;
    preimages[0] = opening("\"2023-12-31T12:00:00Z\"".as_bytes());
    main([[0; 32]; 6], lengths, 1704067200000, 7, preimages);
}

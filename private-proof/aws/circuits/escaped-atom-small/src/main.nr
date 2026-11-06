use aws_private_json::escaped;
use gcp_private_json::commitment;

// Same relation as the batch; avoid proving seven inactive slots for a short tail.
fn main(
    encoded_commitment: pub [u8; 32], encoded_length: pub u32,
    decoded_commitment: pub [u8; 32], decoded_length: pub u32,
    encoded_preimage: [u8; 80], decoded_preimage: [u8; 80],
) -> pub u8 {
    let encoded: [u8; 64] = commitment::authenticate(encoded_preimage, encoded_length, encoded_commitment);
    let decoded: [u8; 64] = commitment::authenticate(decoded_preimage, decoded_length, decoded_commitment);
    escaped::atom(encoded, encoded_length, decoded, decoded_length)
}

#[test(should_fail_with = "Transcript byte limit")]
fn oversized_encoded_rejects() { let _ = main([0; 32], 65, [0; 32], 1, [0; 80], [0; 80]); }

#[test(should_fail_with = "Encoded atom byte limit")]
fn empty_encoded_rejects() {
    let digest = [55, 71, 8, 255, 247, 113, 157, 213, 151, 158, 200, 117, 213, 108, 210, 40, 111, 109, 60, 247, 236, 49, 122, 59, 37, 99, 42, 171, 40, 236, 55, 187];
    let _ = main(digest, 0, digest, 0, [0; 80], [0; 80]);
}

#[test]
fn authenticates_small_scalar() {
    let mut value = [0; 80];
    value[0] = 116; value[1] = 114; value[2] = 117; value[3] = 101;
    for i in 4..20 { value[i] = 7; }
    let digest = [78, 25, 134, 10, 120, 76, 226, 132, 0, 51, 153, 240, 225, 72, 125, 94, 63, 99, 252, 179, 178, 66, 241, 166, 147, 135, 206, 141, 88, 103, 95, 38];
    assert(main(digest, 4, digest, 4, value, value) == 3);
}

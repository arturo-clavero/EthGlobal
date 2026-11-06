use aws_private_json::escaped;
use gcp_private_json::commitment;

fn main(
    encoded_hashes: pub [[u8; 32]; 8], encoded_lengths: pub [u32; 8],
    decoded_hashes: pub [[u8; 32]; 8], decoded_lengths: pub [u32; 8], kinds: pub [u8; 8],
    encoded_preimages: [[u8; 80]; 8], decoded_preimages: [[u8; 80]; 8],
) {
    for i in 0..8 {
        if encoded_lengths[i] == 0 {
            assert((encoded_hashes[i] == [0; 32]) & (decoded_hashes[i] == [0; 32]) &
                (decoded_lengths[i] == 0) & (kinds[i] == 0), "Inactive bridge metadata must be zero");
        } else {
            let encoded: [u8; 64] = commitment::authenticate(encoded_preimages[i], encoded_lengths[i], encoded_hashes[i]);
            let decoded: [u8; 64] = commitment::authenticate(decoded_preimages[i], decoded_lengths[i], decoded_hashes[i]);
            assert(escaped::atom(encoded, encoded_lengths[i], decoded, decoded_lengths[i]) == kinds[i], "Bridge kind mismatch");
        }
    }
}

fn opening() -> [u8; 80] {
    let mut value = [0; 80];
    value[0] = 116; value[1] = 114; value[2] = 117; value[3] = 101;
    for i in 4..20 { value[i] = 7; }
    value
}

fn digest() -> [u8; 32] {
    [78, 25, 134, 10, 120, 76, 226, 132, 0, 51, 153, 240, 225, 72, 125, 94, 63, 99, 252, 179, 178, 66, 241, 166, 147, 135, 206, 141, 88, 103, 95, 38]
}

#[test]
fn all_inactive_bridges_accept() { main([[0; 32]; 8], [0; 8], [[0; 32]; 8], [0; 8], [0; 8], [[0; 80]; 8], [[0; 80]; 8]); }

#[test]
fn all_eight_bridges_authenticate_both_sides() {
    main([digest(); 8], [4; 8], [digest(); 8], [4; 8], [3; 8], [opening(); 8], [opening(); 8]);
}

#[test(should_fail_with = "Inactive bridge metadata must be zero")]
fn inactive_encoded_hash_rejects() {
    main([[1; 32]; 8], [0; 8], [[0; 32]; 8], [0; 8], [0; 8], [[0; 80]; 8], [[0; 80]; 8]);
}

#[test(should_fail_with = "Inactive bridge metadata must be zero")]
fn inactive_decoded_hash_rejects() {
    main([[0; 32]; 8], [0; 8], [[1; 32]; 8], [0; 8], [0; 8], [[0; 80]; 8], [[0; 80]; 8]);
}

#[test(should_fail_with = "Inactive bridge metadata must be zero")]
fn inactive_decoded_length_rejects() {
    main([[0; 32]; 8], [0; 8], [[0; 32]; 8], [1; 8], [0; 8], [[0; 80]; 8], [[0; 80]; 8]);
}

#[test(should_fail_with = "Inactive bridge metadata must be zero")]
fn inactive_kind_rejects() {
    main([[0; 32]; 8], [0; 8], [[0; 32]; 8], [0; 8], [3; 8], [[0; 80]; 8], [[0; 80]; 8]);
}

#[test(should_fail_with = "Transcript byte limit")]
fn oversized_encoded_rejects() { main([digest(); 8], [65; 8], [digest(); 8], [4; 8], [3; 8], [opening(); 8], [opening(); 8]); }

#[test(should_fail_with = "Transcript byte limit")]
fn oversized_decoded_rejects() { main([digest(); 8], [4; 8], [digest(); 8], [65; 8], [3; 8], [opening(); 8], [opening(); 8]); }

#[test(should_fail_with = "Bridge kind mismatch")]
fn last_kind_rejects() {
    let mut kinds = [3; 8]; kinds[7] = 2;
    main([digest(); 8], [4; 8], [digest(); 8], [4; 8], kinds, [opening(); 8], [opening(); 8]);
}

#[test(should_fail)]
fn last_encoded_opening_rejects() {
    let mut values = [opening(); 8]; values[7][0] = 102;
    main([digest(); 8], [4; 8], [digest(); 8], [4; 8], [3; 8], values, [opening(); 8]);
}

#[test(should_fail)]
fn last_decoded_opening_rejects() {
    let mut values = [opening(); 8]; values[7][0] = 102;
    main([digest(); 8], [4; 8], [digest(); 8], [4; 8], [3; 8], [opening(); 8], values);
}

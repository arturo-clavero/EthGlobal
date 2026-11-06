use gcp_private_json::{atomic, commitment};

fn main(hashes: pub [[u8; 32]; 16], lengths: pub [u32; 16], preimages: [[u8; 80]; 16]) {
    for i in 0..16 {
        if lengths[i] == 0 {
            assert(hashes[i] == [0; 32], "Inactive header hash must be zero");
        } else {
            let bytes: [u8; 64] = commitment::authenticate(preimages[i], lengths[i], hashes[i]);
            atomic::header_value(bytes, lengths[i]);
        }
    }
}

fn opening<let N: u32>(value: [u8; N]) -> [u8; 80] {
    let mut result = [0; 80];
    for i in 0..N { result[i] = value[i]; }
    for i in 0..16 { result[N + i] = 7; }
    result
}

#[test]
fn all_inactive_headers_accept_zero_hashes() { main([[0; 32]; 16], [0; 16], [[0; 80]; 16]); }

#[test(should_fail_with = "Inactive header hash must be zero")]
fn inactive_header_cannot_carry_a_commitment() {
    let mut hashes = [[0; 32]; 16]; hashes[15][0] = 1;
    main(hashes, [0; 16], [[0; 80]; 16]);
}

#[test(should_fail_with = "Transcript byte limit")]
fn header_cannot_exceed_small_capacity() { main([[0; 32]; 16], [65; 16], [[0; 80]; 16]); }

#[test]
fn all_sixteen_headers_open_their_commitments() {
    main([[199, 221, 135, 97, 200, 13, 11, 51, 24, 72, 120, 182, 45, 63, 138, 109, 21, 17, 122, 70, 122, 53, 112, 195, 17, 96, 158, 215, 194, 27, 11, 62]; 16], [7; 16], [opening("private".as_bytes()); 16]);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn last_header_cannot_use_another_hash() {
    let mut hashes = [[199, 221, 135, 97, 200, 13, 11, 51, 24, 72, 120, 182, 45, 63, 138, 109, 21, 17, 122, 70, 122, 53, 112, 195, 17, 96, 158, 215, 194, 27, 11, 62]; 16]; hashes[15][0] = 0;
    main(hashes, [7; 16], [opening("private".as_bytes()); 16]);
}

#[test(should_fail_with = "Invalid hidden header value")]
fn authenticated_header_crlf_is_rejected() {
    main([[52, 133, 164, 2, 20, 39, 98, 165, 74, 173, 215, 56, 9, 152, 191, 188, 131, 101, 63, 36, 181, 107, 81, 180, 102, 126, 133, 86, 173, 153, 85, 164]; 16], [4; 16], [opening([120,13,10,89]); 16]);
}

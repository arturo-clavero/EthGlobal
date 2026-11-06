use gcp_private_json::{atomic, commitment};

fn main(hashes: pub [[u8; 32]; 8], lengths: pub [u32; 8], kinds: pub [u8; 8], preimages: [[u8; 80]; 8]) {
    for i in 0..8 {
        if lengths[i] == 0 {
            assert((hashes[i] == [0; 32]) & (kinds[i] == 0), "Inactive atom hash and kind must be zero");
        } else {
            let bytes: [u8; 64] = commitment::authenticate(preimages[i], lengths[i], hashes[i]);
            assert(atomic::json_atom(bytes, lengths[i]) == kinds[i], "Authenticated atom kind mismatch");
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
fn all_inactive_atoms_accept_zero_hashes_and_kinds() { main([[0; 32]; 8], [0; 8], [0; 8], [[0; 80]; 8]); }

#[test(should_fail_with = "Inactive atom hash and kind must be zero")]
fn inactive_atom_cannot_claim_a_kind() { main([[0; 32]; 8], [0; 8], [1; 8], [[0; 80]; 8]); }

#[test(should_fail_with = "Inactive atom hash and kind must be zero")]
fn inactive_atom_cannot_carry_a_commitment() {
    let mut hashes = [[0; 32]; 8]; hashes[7][0] = 1;
    main(hashes, [0; 8], [0; 8], [[0; 80]; 8]);
}

#[test(should_fail_with = "Transcript byte limit")]
fn atom_cannot_exceed_small_capacity() { main([[0; 32]; 8], [65; 8], [1; 8], [[0; 80]; 8]); }

#[test]
fn all_eight_atoms_open_and_match_public_kind() {
    main([[193, 98, 100, 162, 41, 59, 161, 2, 189, 84, 202, 218, 86, 102, 241, 93, 84, 201, 109, 4, 85, 238, 68, 95, 76, 167, 61, 13, 236, 191, 40, 186]; 8], [3; 8], [1; 8], [opening([34,65,34]); 8]);
}

#[test(should_fail_with = "Authenticated atom kind mismatch")]
fn last_atom_cannot_claim_the_wrong_kind() {
    let mut kinds = [1; 8]; kinds[7] = 2;
    main([[193, 98, 100, 162, 41, 59, 161, 2, 189, 84, 202, 218, 86, 102, 241, 93, 84, 201, 109, 4, 85, 238, 68, 95, 76, 167, 61, 13, 236, 191, 40, 186]; 8], [3; 8], kinds, [opening([34,65,34]); 8]);
}

#[test(should_fail_with = "Trailing bytes after JSON atom")]
fn authenticated_comma_injection_is_rejected() {
    main([[32, 182, 16, 43, 222, 164, 176, 8, 206, 162, 16, 205, 207, 131, 164, 89, 217, 138, 1, 202, 155, 130, 117, 160, 158, 92, 86, 216, 27, 229, 111, 149]; 8], [5; 8], [1; 8], [opening([34,65,34,44,48]); 8]);
}

// TLSNotary commits to transcript[0..length] followed by a private 16-byte blinder.
// The verifier must bind expected/length to the authenticated TLS session result.
pub fn authenticate<let N: u32>(preimage: [u8; N + 16], length: u32, expected: [u8; 32]) -> [u8; N] {
    assert(length <= N, "Transcript byte limit");
    assert(sha256::sha256_var(preimage, length + 16) == expected, "Transcript commitment mismatch");
    // This static prefix copy has no masked writes or dynamic blinder insertion.
    // Consumers must honor length; bytes after it may include the private blinder.
    let mut transcript = [0u8; N];
    for i in 0..N { transcript[i] = preimage[i]; }
    transcript
}

// Reference digest generated independently with Python hashlib.sha256.
#[test]
fn opening_returns_the_authenticated_prefix() {
    let preimage = [97, 98, 99, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    assert(authenticate::<3>(preimage, 3, [211, 207, 130, 71, 79, 52, 197, 218, 101, 205, 27, 16, 80, 45, 137, 25, 187, 111, 231, 234, 220, 125, 124, 31, 254, 138, 207, 117, 158, 168, 36, 242]) == "abc".as_bytes());
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn changed_private_prefix_is_rejected() {
    let mut preimage = [97, 98, 99, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    preimage[0] = 100;
    let _ = authenticate::<3>(preimage, 3, [211, 207, 130, 71, 79, 52, 197, 218, 101, 205, 27, 16, 80, 45, 137, 25, 187, 111, 231, 234, 220, 125, 124, 31, 254, 138, 207, 117, 158, 168, 36, 242]);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn changed_authenticated_length_is_rejected() {
    let preimage = [97, 98, 99, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let _ = authenticate::<3>(preimage, 2, [211, 207, 130, 71, 79, 52, 197, 218, 101, 205, 27, 16, 80, 45, 137, 25, 187, 111, 231, 234, 220, 125, 124, 31, 254, 138, 207, 117, 158, 168, 36, 242]);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn changed_public_hash_is_rejected() {
    let preimage = [97, 98, 99, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let mut hash = [211, 207, 130, 71, 79, 52, 197, 218, 101, 205, 27, 16, 80, 45, 137, 25, 187, 111, 231, 234, 220, 125, 124, 31, 254, 138, 207, 117, 158, 168, 36, 242];
    hash[0] = hash[0] ^ 1;
    let _ = authenticate::<3>(preimage, 3, hash);
}

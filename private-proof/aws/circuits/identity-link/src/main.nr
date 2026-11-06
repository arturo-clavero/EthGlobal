mod identity;
use gcp_private_json::commitment;

fn quoted_match<let N: u32, let M: u32>(value: [u8; N], length: u32, quoted: [u8; M], quoted_length: u32) {
    assert((length <= N) & (quoted_length <= M) & (quoted_length == length + 2), "Identity JSON length mismatch");
    assert((quoted[0] == 34) & (quoted[quoted_length - 1] == 34), "Identity JSON quotes");
    for i in 0..N { if i < length { assert(value[i] == quoted[i + 1], "Identity JSON value mismatch"); } }
}

// Fixed slots: raw IAM UserId/Arn/Path/UserName, then decoded JSON actor
// principalId/arn/accountId and recipientAccountId. The verifier binds every slot
// to its authenticated session and field position.
fn main(
    hashes: pub [[u8; 32]; 8], lengths: pub [u32; 8],
    id_preimage: [u8; 144], arn_preimage: [u8; 528], path_preimage: [u8; 528], user_preimage: [u8; 80],
    actor_id_preimage: [u8; 146], actor_arn_preimage: [u8; 530],
    actor_account_preimage: [u8; 30], recipient_preimage: [u8; 30],
) {
    // Authenticate full preimages before relating values, as in the shared library.
    // Constructing fixed account openings here triggers beta.19's constraint-check diagnostic.
    let id = commitment::authenticate(id_preimage, lengths[0], hashes[0]);
    let arn = commitment::authenticate(arn_preimage, lengths[1], hashes[1]);
    let path = commitment::authenticate(path_preimage, lengths[2], hashes[2]);
    let user = commitment::authenticate(user_preimage, lengths[3], hashes[3]);
    let account = identity::validate(id, lengths[0], arn, lengths[1], path, lengths[2], user, lengths[3]);
    quoted_match(id, lengths[0], commitment::authenticate(actor_id_preimage, lengths[4], hashes[4]), lengths[4]);
    quoted_match(arn, lengths[1], commitment::authenticate(actor_arn_preimage, lengths[5], hashes[5]), lengths[5]);
    quoted_match(account, 12, commitment::authenticate(actor_account_preimage, lengths[6], hashes[6]), lengths[6]);
    quoted_match(account, 12, commitment::authenticate(recipient_preimage, lengths[7], hashes[7]), lengths[7]);
}

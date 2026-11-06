mod tests;

fn reference(hash: [u8; 32], preimage: [u8; 54]) -> [u8; 36] {
    let quoted = source::commitment::authenticate::<38>(preimage, 38, hash);
    assert((quoted[0] == 34) & (quoted[37] == 34), "Expected quoted claims reference");
    let mut id = [0u8; 36]; for i in 0..36 { id[i] = quoted[i + 1]; } id
}

// Hash roles: native chunk, incoming private state, outgoing private state, derived actor, derived tenant.
fn main(hashes: pub [[u8; 32]; 5], length: pub u32, offset: pub u32, total: pub u32,
    chunk_preimage: [u8; 528], state_preimages: [[u8; 99]; 2], identity_preimages: [[u8; 54]; 2]) {
    let chunk = source::commitment::authenticate::<512>(chunk_preimage, length, hashes[0]);
    let before = source::commitment::authenticate::<83>(state_preimages[0], 83, hashes[1]);
    let after = source::commitment::authenticate::<83>(state_preimages[1], 83, hashes[2]);
    let actor = reference(hashes[3], identity_preimages[0]);
    let tenant = reference(hashes[4], identity_preimages[1]);
    assert(azure::claims::transition(chunk, length, before, offset, total, actor, tenant) == after, "Claims state transition mismatch");
}

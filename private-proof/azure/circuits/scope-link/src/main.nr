mod tests;

fn uuid(bytes: [u8; 38]) -> [u8; 36] {
    assert((bytes[0] == 34) & (bytes[37] == 34), "Expected quoted Azure UUID");
    let mut value = [0u8; 36];
    for i in 0..36 {
        let byte = bytes[i + 1];
        let c = if (byte >= 65) & (byte <= 70) { byte + 32 } else { byte };
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) {
            assert(c == 45, "Invalid Azure UUID");
        } else {
            assert(((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)), "Invalid Azure UUID");
        }
        value[i] = c;
    }
    value
}

// The receipt inspector must derive these slots from authenticated fields in the same attempt.
// Pairs: Graph/Activity actor, ARM/Activity tenant, ARM/Activity subscription.
fn main(hashes: pub [[u8; 32]; 6], preimages: [[u8; 54]; 6]) {
    let mut ids = [[0u8; 36]; 6];
    for i in 0..6 {
        ids[i] = uuid(source::commitment::authenticate::<38>(preimages[i], 38, hashes[i]));
    }
    assert(ids[0] == ids[1], "Wrong Activity actor");
    assert(ids[2] == ids[3], "Wrong Activity tenant");
    assert(ids[4] == ids[5], "Wrong Activity subscription");
}

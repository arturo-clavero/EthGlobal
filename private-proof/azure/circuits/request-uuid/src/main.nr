mod tests;

fn uuid(bytes: [u8; 36]) -> [u8; 36] {
    let mut value = [0u8; 36];
    for i in 0..36 {
        let byte = bytes[i];
        let c = if (byte >= 65) & (byte <= 70) { byte + 32 } else { byte };
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) {
            assert(c == 45, "Invalid request UUID");
        } else {
            assert(((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)), "Invalid request UUID");
        }
        value[i] = c;
    }
    value
}

// The inspector must authenticate both field roles and the same attempt separately.
fn main(hashes: pub [[u8; 32]; 2], request_preimage: [u8; 52], reference_preimage: [u8; 54]) {
    let request = source::commitment::authenticate::<36>(request_preimage, 36, hashes[0]);
    let reference = source::commitment::authenticate::<38>(reference_preimage, 38, hashes[1]);
    assert((reference[0] == 34) & (reference[37] == 34), "Expected quoted UUID reference");
    let mut unquoted = [0u8; 36];
    for i in 0..36 { unquoted[i] = reference[i + 1]; }
    assert(uuid(request) == uuid(unquoted), "Request UUID scope mismatch");
}

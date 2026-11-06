mod tests;

fn matches<let N: u32>(key: [u8; 64], length: u32, expected: [u8; N]) -> bool {
    let mut same = length == N + 2;
    for i in 0..N { same = same & (key[i + 1] == expected[i]); }
    same
}

// The inspector permits one private extra key with an array containing this one opaque object.
fn main(hashes: pub [[u8; 32]; 2], lengths: pub [u32; 2], key_preimage: [u8; 80], object_preimage: [u8; 144]) {
    let key = source::commitment::authenticate::<64>(key_preimage, lengths[0], hashes[0]);
    assert((lengths[0] >= 3) & (lengths[0] <= 64), "Invalid private tenant key length");
    assert((key[0] == 34) & (key[lengths[0] - 1] == 34), "Expected quoted private tenant key");
    for i in 1..63 {
        if i < lengths[0] - 1 {
            let c = key[i];
            assert((c >= 32) & (c <= 126) & (c != 34) & (c != 92), "Noncanonical private tenant key");
        }
    }
    let reserved = matches(key, lengths[0], "subscriptionId".as_bytes())
        | matches(key, lengths[0], "tenantId".as_bytes()) | matches(key, lengths[0], "state".as_bytes())
        | matches(key, lengths[0], "id".as_bytes()) | matches(key, lengths[0], "displayName".as_bytes())
        | matches(key, lengths[0], "authorizationSource".as_bytes())
        | matches(key, lengths[0], "subscriptionPolicies".as_bytes())
        | matches(key, lengths[0], "managedByTenants".as_bytes()) | matches(key, lengths[0], "tags".as_bytes());
    assert(!reserved, "Private tenant key shadows a reserved field");
    let object = source::commitment::authenticate::<128>(object_preimage, lengths[1], hashes[1]);
    let parsed: source::json::Json<16> = source::json::parse(object, lengths[1]);
    assert(parsed.nodes[0].kind == 2, "Expected private tenant metadata object");
}

mod tests;

fn lower(c: u8) -> u8 { if (c >= 65) & (c <= 90) { c + 32 } else { c } }

fn string<let N: u32>(bytes: [u8; N], length: u32) -> ([u8; N], u32) {
    assert((length >= 2) & (length <= N), "Invalid ARG string length");
    assert((bytes[0] == 34) & (bytes[length - 1] == 34), "Expected quoted ARG string");
    let mut value = [0u8; N];
    for i in 0..N - 2 {
        if i < length - 2 {
            let c = bytes[i + 1];
            assert((c >= 32) & (c <= 126) & (c != 34) & (c != 92), "Unsupported ARG string byte");
            value[i] = lower(c);
        }
    }
    (value, length - 2)
}

fn priority(bytes: [u8; 6], length: u32) {
    let kind = source::atomic::json_atom(bytes, length);
    assert((kind == 1) | (kind == 2) | (kind == 5), "Unsupported ARG priority kind");
    if kind != 5 {
        let start = if kind == 1 { 1 } else { 0 };
        let digits = length - if kind == 1 { 2 } else { 0 };
        assert((digits == 3) | (digits == 4), "Invalid ARG priority digits");
        let mut value: u32 = 0;
        for i in 0..4 {
            if i < digits {
                let c = bytes[start + i];
                assert((c >= 48) & (c <= 57), "Invalid ARG priority digit");
                value = value * 10 + (c - 48) as u32;
            }
        }
        assert((value >= 100) & (value <= 4096), "ARG priority outside domain");
    }
}

// shortcut: named ASCII selectors and priority only; add other shapes after measuring this component.
fn check(key: [u8; 192], before: [u8; 6], after: [u8; 6], resource: [u8; 514], lengths: [u32; 4]) {
    let (key, key_len) = string(key, lengths[0]);
    let (resource, resource_len) = string(resource, lengths[3]);
    let mut rule_parts = [0 as Field; 5];
    let mut rule_len = 0;
    let mut rule_parent = false;
    let mut marker = 0 as Field;
    for c in "securityrules".as_bytes() { marker = marker * 256 + c as Field; }
    for i in 0..514 {
        if i < resource_len {
            let c = resource[i];
            if c == 47 {
                rule_parent = (rule_len == 13) & (rule_parts[0] == marker);
                rule_parts = [0 as Field; 5]; rule_len = 0;
            } else {
                if rule_len < 128 {
                    let limb = rule_len / 31;
                    rule_parts[limb] = rule_parts[limb] * 256 + c as Field;
                }
                rule_len += 1;
            }
        }
    }
    assert((resource[0] == 47) & rule_parent, "Invalid Activity rule suffix");
    assert((rule_len > 0) & (rule_len <= 128), "Unsupported ARG rule length");
    assert(key_len == 25 + rule_len + 21, "Invalid ARG priority path");
    let prefix = "properties.securityrules[".as_bytes();
    let suffix = "].properties.priority".as_bytes();
    for i in 0..25 { assert(key[i] == prefix[i], "Invalid ARG priority path"); }
    for i in 0..21 { assert(key[25 + rule_len + i] == suffix[i], "Invalid ARG priority path"); }
    let mut named = false;
    let mut key_parts = [0 as Field; 5];
    for i in 0..128 {
        if i < rule_len {
            let c = key[25 + i];
            let digit = (c >= 48) & (c <= 57);
            assert(((c >= 97) & (c <= 122)) | digit | (c == 45) | (c == 46) | (c == 95) | (c == 40) | (c == 41), "Unsupported ARG rule name");
            named = named | !digit;
            key_parts[i / 31] = key_parts[i / 31] * 256 + c as Field;
        }
    }
    // Each limb holds at most 31 bytes, so equality is exact rather than a probabilistic digest.
    assert(key_parts == rule_parts, "ARG rule does not match Activity");
    assert(named, "Numeric ARG selector unsupported");
    priority(before, lengths[1]); priority(after, lengths[2]);
    let mut same = lengths[1] == lengths[2];
    for i in 0..6 { if i < lengths[1] { same = same & (before[i] == after[i]); } }
    assert(!same, "ARG priority is a no-op");
}

// The verifier must bind these exact slots to one ARG record and the accepted Activity resource.
fn main(hashes: pub [[u8; 32]; 4], lengths: pub [u32; 4], key: [u8; 208],
    before: [u8; 22], after: [u8; 22], resource: [u8; 530]) {
    check(source::commitment::authenticate::<192>(key, lengths[0], hashes[0]),
        source::commitment::authenticate::<6>(before, lengths[1], hashes[1]),
        source::commitment::authenticate::<6>(after, lengths[2], hashes[2]),
        source::commitment::authenticate::<514>(resource, lengths[3], hashes[3]), lengths);
}

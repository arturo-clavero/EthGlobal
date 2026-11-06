mod tests;

fn lower(c: u8) -> u8 { if (c >= 65) & (c <= 90) { c + 32 } else { c } }

fn string<let N: u32>(bytes: [u8; N + 2], length: u32) -> ([u8; N], u32) {
    assert((length >= 2) & (length <= N + 2), "Invalid ARG link string length");
    assert((bytes[0] == 34) & (bytes[length - 1] == 34), "Expected quoted ARG link string");
    let mut value = [0u8; N];
    for i in 0..N {
        if i < length - 2 {
            let c = bytes[i + 1];
            assert((c >= 32) & (c <= 126) & (c != 34) & (c != 92), "Unsupported ARG link string byte");
            value[i] = c;
        }
    }
    (value, length - 2)
}

fn uuid(bytes: [u8; 38]) -> [u8; 36] {
    let (mut value, _) = string::<36>(bytes, 38);
    for i in 0..36 {
        let c = lower(value[i]);
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) { assert(c == 45, "Invalid ARG link UUID"); }
        else { assert(((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)), "Invalid ARG link UUID"); }
        value[i] = c;
    }
    value
}

fn check(target: [u8; 512], target_len: u32, activity: [u8; 512], activity_len: u32,
    correlations: [[u8; 36]; 2], timestamp: [u8; 30], time_len: u32, cutoff_ms: u64) {
    assert(correlations[0] == correlations[1], "ARG correlation does not match Activity");
    assert((target_len > 0) & (target_len <= activity_len) & (activity_len <= 512), "Invalid ARG target length");
    assert((target[0] == 47) & (activity[0] == 47), "Expected ARM resource paths");
    for i in 0..512 {
        if i < activity_len {
            let c = lower(activity[i]);
            assert(((c >= 97) & (c <= 122)) | ((c >= 48) & (c <= 57)) |
                (c == 47) | (c == 45) | (c == 46) | (c == 95) | (c == 40) | (c == 41), "Unsupported ARG link resource byte");
        }
        if i < target_len { assert(lower(target[i]) == lower(activity[i]), "ARG target does not match Activity"); }
    }
    if target_len != activity_len {
        let marker = "/securityrules/".as_bytes();
        assert(target_len + 15 < activity_len, "ARG target is not the NSG parent");
        for i in 0..15 { assert(lower(activity[target_len + i]) == marker[i], "ARG target is not the NSG parent"); }
        for i in 0..512 {
            if (i >= target_len + 15) & (i < activity_len) { assert(activity[i] != 47, "ARG target is not the NSG parent"); }
        }
    }
    assert(cutoff_ms <= 8640000000000000, "Invalid Azure cutoff");
    let _ = source::json::timestamp_day(timestamp, time_len, cutoff_ms, 14);
}

// Reuse the accepted Activity resource/correlation hashes and cutoff; labels alone establish no join.
fn main(hashes: pub [[u8; 32]; 5], lengths: pub [u32; 3], cutoff_ms: pub u64,
    resources: [[u8; 530]; 2], correlations: [[u8; 54]; 2], timestamp: [u8; 48]) {
    let (target, target_len) = string::<512>(source::commitment::authenticate::<514>(resources[0], lengths[0], hashes[0]), lengths[0]);
    let arg_correlation = uuid(source::commitment::authenticate::<38>(correlations[0], 38, hashes[1]));
    let (time, time_len) = string::<30>(source::commitment::authenticate::<32>(timestamp, lengths[1], hashes[2]), lengths[1]);
    let (activity, activity_len) = string::<512>(source::commitment::authenticate::<514>(resources[1], lengths[2], hashes[3]), lengths[2]);
    let activity_correlation = uuid(source::commitment::authenticate::<38>(correlations[1], 38, hashes[4]));
    check(target, target_len, activity, activity_len, [arg_correlation, activity_correlation], time, time_len, cutoff_ms);
}

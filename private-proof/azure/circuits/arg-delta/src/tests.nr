use super::{check, priority, main};

fn pad<let N: u32, let M: u32>(value: [u8; M]) -> [u8; N] {
    assert(M <= N); let mut result = [0u8; N];
    for i in 0..M { result[i] = value[i]; } result
}

fn delta<let B: u32, let A: u32>(before: [u8; B], after: [u8; A]) {
    let key = "\"properties.securityRules[PRIVATE-RULE].properties.priority\"".as_bytes();
    let resource = "\"/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG/securityRules/PRIVATE-RULE\"".as_bytes();
    check(pad(key), pad(before), pad(after), pad(resource), [key.len(), B, A, resource.len()]);
}

#[test]
fn accepts_addition() { delta("null".as_bytes(), "\"400\"".as_bytes()); }

#[test]
fn accepts_removal() { delta("400".as_bytes(), "null".as_bytes()); }

#[test]
fn accepts_change() { delta("100".as_bytes(), "4096".as_bytes()); }

#[test]
fn accepts_string_leading_zero() { delta("\"0100\"".as_bytes(), "\"100\"".as_bytes()); }

#[test]
fn accepts_type_change() { delta("400".as_bytes(), "\"400\"".as_bytes()); }

#[test(should_fail_with = "ARG priority is a no-op")]
fn rejects_numeric_noop() { delta("400".as_bytes(), "400".as_bytes()); }

#[test(should_fail_with = "ARG priority is a no-op")]
fn rejects_string_noop() { delta("\"400\"".as_bytes(), "\"400\"".as_bytes()); }

#[test(should_fail_with = "ARG priority is a no-op")]
fn rejects_both_null() { delta("null".as_bytes(), "null".as_bytes()); }

#[test(should_fail_with = "Invalid ARG priority digits")]
fn rejects_low() { let value = "99".as_bytes(); priority(pad(value), value.len()); }

#[test(should_fail_with = "ARG priority outside domain")]
fn rejects_zero() { let value = "\"0000\"".as_bytes(); priority(pad(value), value.len()); }

#[test(should_fail_with = "ARG priority outside domain")]
fn rejects_high() { let value = "4097".as_bytes(); priority(pad(value), value.len()); }

#[test(should_fail_with = "Unsupported ARG priority kind")]
fn rejects_boolean() { let value = "true".as_bytes(); priority(pad(value), value.len()); }

#[test(should_fail_with = "Invalid ARG priority digit")]
fn rejects_quoted_null() { let value = "\"null\"".as_bytes(); priority(pad(value), value.len()); }

#[test(should_fail_with = "Invalid ARG priority digit")]
fn rejects_negative() { let value = "-100".as_bytes(); priority(pad(value), value.len()); }

#[test(should_fail_with = "Invalid ARG priority digits")]
fn rejects_fraction() { let value = "100.5".as_bytes(); priority(pad(value), value.len()); }

#[test(should_fail_with = "Invalid ARG priority digit")]
fn rejects_exponent() { let value = "1e3".as_bytes(); priority(pad(value), value.len()); }

#[test(should_fail_with = "ARG rule does not match Activity")]
fn rejects_different_rule() { let key = "\"properties.securityRules[PRIVATE-RULX].properties.priority\"".as_bytes(); let resource = "\"/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG/securityRules/PRIVATE-RULE\"".as_bytes(); check(pad(key), pad("null".as_bytes()), pad("400".as_bytes()), pad(resource), [key.len(), 4, 3, resource.len()]); }

#[test(should_fail_with = "Numeric ARG selector unsupported")]
fn rejects_numeric_selector() { let key = "\"properties.securityRules[123].properties.priority\"".as_bytes(); let resource = "\"/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG/securityRules/123\"".as_bytes(); check(pad(key), pad("null".as_bytes()), pad("400".as_bytes()), pad(resource), [key.len(), 4, 3, resource.len()]); }

#[test(should_fail_with = "Invalid ARG priority path")]
fn rejects_other_field() { let key = "\"properties.securityRules[PRIVATE-RULE].properties.access\"".as_bytes(); let resource = "\"/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG/securityRules/PRIVATE-RULE\"".as_bytes(); check(pad(key), pad("null".as_bytes()), pad("400".as_bytes()), pad(resource), [key.len(), 4, 3, resource.len()]); }

#[test(should_fail_with = "Unsupported ARG string byte")]
fn rejects_escaped_selector() { let key = "\"properties.securityRules[PRIVATE\\u002dRULE].properties.priority\"".as_bytes(); let resource = "\"/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG/securityRules/PRIVATE-RULE\"".as_bytes(); check(pad(key), pad("null".as_bytes()), pad("400".as_bytes()), pad(resource), [key.len(), 4, 3, resource.len()]); }

#[test(should_fail_with = "Unsupported ARG rule name")]
fn rejects_unknown_name_byte() { let key = "\"properties.securityRules[PRIVATE+RULE].properties.priority\"".as_bytes(); let resource = "\"/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG/securityRules/PRIVATE+RULE\"".as_bytes(); check(pad(key), pad("null".as_bytes()), pad("400".as_bytes()), pad(resource), [key.len(), 4, 3, resource.len()]); }

#[test(should_fail_with = "Invalid Activity rule suffix")]
fn rejects_wrong_resource_kind() { let key = "\"properties.securityRules[PRIVATE-RULE].properties.priority\"".as_bytes(); let resource = "\"/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/PRIVATE-GROUP/providers/Microsoft.Network/networkSecurityGroups/PRIVATE-NSG/securityRulxs/PRIVATE-RULE\"".as_bytes(); check(pad(key), pad("null".as_bytes()), pad("400".as_bytes()), pad(resource), [key.len(), 4, 3, resource.len()]); }

#[test]
fn accepts_case_normalized_private_path() { let key = "\"PROPERTIES.SECURITYRULES[PRIVATE-RULE].PROPERTIES.PRIORITY\"".as_bytes(); let resource = "\"/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/private-nsg/securityrules/private-rule\"".as_bytes(); check(pad(key), pad("null".as_bytes()), pad("400".as_bytes()), pad(resource), [key.len(), 4, 3, resource.len()]); }

struct Witness { hashes: [[u8; 32]; 4], lengths: [u32; 4], key: [u8; 208], before: [u8; 22], after: [u8; 22], resource: [u8; 530] }

// Independent Python hashlib commitments over exact JSON atoms and distinct blinders.
fn fixture() -> Witness {
    Witness {
        hashes: [
            [210, 104, 152, 223, 23, 92, 33, 178, 221, 242, 48, 71, 58, 109, 147, 15, 7, 2, 222, 191, 204, 102, 57, 234, 76, 17, 165, 28, 28, 223, 116, 127],
            [108, 117, 223, 76, 90, 236, 236, 251, 187, 150, 246, 108, 45, 25, 152, 197, 121, 81, 42, 245, 127, 211, 25, 94, 239, 98, 2, 200, 128, 203, 251, 125],
            [222, 10, 130, 58, 27, 219, 101, 210, 179, 41, 188, 49, 103, 22, 184, 8, 136, 12, 139, 64, 137, 196, 175, 127, 65, 134, 14, 99, 104, 18, 173, 84],
            [194, 237, 143, 224, 41, 230, 236, 128, 44, 112, 107, 133, 214, 45, 126, 167, 112, 33, 83, 101, 215, 76, 79, 238, 245, 135, 118, 216, 43, 148, 215, 191],
        ],
        lengths: [60, 4, 5, 171],
        key: pad([34, 112, 114, 111, 112, 101, 114, 116, 105, 101, 115, 46, 115, 101, 99, 117, 114, 105, 116, 121, 82, 117, 108, 101, 115, 91, 80, 82, 73, 86, 65, 84, 69, 45, 82, 85, 76, 69, 93, 46, 112, 114, 111, 112, 101, 114, 116, 105, 101, 115, 46, 112, 114, 105, 111, 114, 105, 116, 121, 34, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]),
        before: pad([110, 117, 108, 108, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]),
        after: pad([34, 52, 48, 48, 34, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]),
        resource: pad([34, 47, 115, 117, 98, 115, 99, 114, 105, 112, 116, 105, 111, 110, 115, 47, 99, 99, 99, 99, 99, 99, 99, 99, 45, 49, 49, 49, 49, 45, 50, 50, 50, 50, 45, 51, 51, 51, 51, 45, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 47, 114, 101, 115, 111, 117, 114, 99, 101, 71, 114, 111, 117, 112, 115, 47, 80, 82, 73, 86, 65, 84, 69, 45, 71, 82, 79, 85, 80, 47, 112, 114, 111, 118, 105, 100, 101, 114, 115, 47, 77, 105, 99, 114, 111, 115, 111, 102, 116, 46, 78, 101, 116, 119, 111, 114, 107, 47, 110, 101, 116, 119, 111, 114, 107, 83, 101, 99, 117, 114, 105, 116, 121, 71, 114, 111, 117, 112, 115, 47, 80, 82, 73, 86, 65, 84, 69, 45, 78, 83, 71, 47, 115, 101, 99, 117, 114, 105, 116, 121, 82, 117, 108, 101, 115, 47, 80, 82, 73, 86, 65, 84, 69, 45, 82, 85, 76, 69, 34, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4]),
    }
}

#[test]
fn authenticated_priority_delta() { let f = fixture(); main(f.hashes, f.lengths, f.key, f.before, f.after, f.resource); }

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_changed_key_commitment() { let mut f = fixture(); f.hashes[0][0] = f.hashes[0][0] ^ 1; main(f.hashes, f.lengths, f.key, f.before, f.after, f.resource); }

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_changed_value_opening() { let mut f = fixture(); f.after[1] = 53; main(f.hashes, f.lengths, f.key, f.before, f.after, f.resource); }

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_changed_resource_opening() { let mut f = fixture(); f.resource[1] = 120; main(f.hashes, f.lengths, f.key, f.before, f.after, f.resource); }

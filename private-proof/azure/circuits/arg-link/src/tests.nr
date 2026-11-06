use super::{check, string, uuid, main};

global CUTOFF: u64 = 1793433600000;

fn pad<let N: u32, let M: u32>(value: [u8; M]) -> [u8; N] {
    assert(M <= N); let mut result = [0u8; N];
    for i in 0..M { result[i] = value[i]; } result
}

fn relation<let T: u32, let A: u32, let S: u32>(target: [u8; T], activity: [u8; A], time: [u8; S]) {
    let id = "ffffffff-1111-2222-3333-444444444444".as_bytes();
    check(pad(target), T, pad(activity), A, [id, id], pad(time), S, CUTOFF);
}

#[test]
fn accepts_exact_rule() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test]
fn accepts_exact_parent() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test]
fn accepts_case_normalization() { relation("/SUBSCRIPTIONS/CCCCCCCC-1111-2222-3333-444444444444/RESOURCEGROUPS/PRIVATE-GROUP/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/PRIVATE-NSG".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/private-nsg/securityrules/private-rule".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test]
fn accepts_fractional_time() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-29T08:00:00.123456789Z".as_bytes()); }

#[test]
fn accepts_window_start() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-17T08:00:00Z".as_bytes()); }

#[test]
fn accepts_window_end() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-31T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "ARG target does not match Activity")]
fn rejects_similar_prefix() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg-other".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "ARG target does not match Activity")]
fn rejects_other_subscription() { relation("/subscriptions/dddddddd-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "ARG target is not the NSG parent")]
fn rejects_trailing_slash() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "ARG target is not the NSG parent")]
fn rejects_wrong_resource_type() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRulxs/private-rule".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "ARG target is not the NSG parent")]
fn rejects_extra_child() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule/nested".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "ARG target is not the NSG parent")]
fn rejects_empty_rule() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "ARG target is not the NSG parent")]
fn rejects_earlier_ancestor() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "Unsupported ARG link resource byte")]
fn rejects_unsupported_name() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private+rule".as_bytes(), "2026-10-29T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "Timestamp before window")]
fn rejects_old_time() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-01T00:00:00Z".as_bytes()); }

#[test(should_fail_with = "Timestamp after window")]
fn rejects_future_time() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-11-01T00:00:00Z".as_bytes()); }

#[test(should_fail_with = "Invalid UTC timestamp")]
fn rejects_non_utc() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-10-29T08:00:00z".as_bytes()); }

#[test(should_fail_with = "Invalid calendar day")]
fn rejects_invalid_day() { relation("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(), "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(), "2026-02-30T08:00:00Z".as_bytes()); }

#[test(should_fail_with = "ARG correlation does not match Activity")]
fn rejects_wrong_correlation() { let id = "ffffffff-1111-2222-3333-444444444444".as_bytes(); let mut other = id; other[0] = 97; let target = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg".as_bytes(); let activity = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourceGroups/private-group/providers/Microsoft.Network/networkSecurityGroups/private-nsg/securityRules/private-rule".as_bytes(); check(pad(target), target.len(), pad(activity), activity.len(), [id, other], pad("2026-10-29T08:00:00Z".as_bytes()), 20, CUTOFF); }

#[test]
fn uuid_case_normalizes() { assert(uuid("\"FFFFFFFF-1111-2222-3333-444444444444\"".as_bytes()) == "ffffffff-1111-2222-3333-444444444444".as_bytes()); }

#[test(should_fail_with = "Invalid ARG link UUID")]
fn rejects_uuid_alias() { let _ = uuid("\"gfffffff-1111-2222-3333-444444444444\"".as_bytes()); }

#[test(should_fail_with = "Unsupported ARG link string byte")]
fn rejects_quoted_atom_injection() { let _ = string::<3>("\"a\"b\"".as_bytes(), 5); }

struct Witness { hashes: [[u8; 32]; 5], lengths: [u32; 3], resources: [[u8; 530]; 2], correlations: [[u8; 54]; 2], timestamp: [u8; 48] }

// Independently generated Python hashlib commitments over exact atoms and distinct blinders.
fn fixture() -> Witness {
    Witness {
        hashes: [
            [137, 4, 114, 86, 122, 146, 86, 131, 94, 132, 145, 212, 72, 40, 208, 222, 253, 197, 154, 77, 232, 72, 115, 244, 235, 126, 69, 255, 161, 86, 72, 238],
            [157, 153, 60, 111, 154, 187, 109, 216, 217, 52, 254, 44, 137, 115, 125, 161, 90, 222, 94, 32, 155, 140, 195, 165, 159, 16, 234, 110, 34, 112, 132, 119],
            [180, 131, 135, 39, 198, 30, 85, 114, 77, 198, 152, 20, 98, 164, 245, 254, 17, 178, 223, 203, 2, 187, 182, 210, 241, 6, 198, 15, 118, 221, 54, 209],
            [36, 153, 211, 147, 167, 2, 214, 73, 62, 210, 127, 97, 69, 197, 197, 181, 181, 133, 21, 141, 220, 24, 62, 204, 64, 247, 83, 6, 158, 121, 13, 171],
            [110, 133, 20, 237, 208, 170, 238, 252, 82, 190, 240, 246, 122, 196, 136, 41, 204, 205, 240, 98, 146, 245, 133, 228, 112, 133, 223, 60, 86, 182, 229, 54],
        ],
        lengths: [144, 22, 171],
        resources: [pad([34, 47, 115, 117, 98, 115, 99, 114, 105, 112, 116, 105, 111, 110, 115, 47, 99, 99, 99, 99, 99, 99, 99, 99, 45, 49, 49, 49, 49, 45, 50, 50, 50, 50, 45, 51, 51, 51, 51, 45, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 47, 114, 101, 115, 111, 117, 114, 99, 101, 71, 114, 111, 117, 112, 115, 47, 112, 114, 105, 118, 97, 116, 101, 45, 103, 114, 111, 117, 112, 47, 112, 114, 111, 118, 105, 100, 101, 114, 115, 47, 77, 105, 99, 114, 111, 115, 111, 102, 116, 46, 78, 101, 116, 119, 111, 114, 107, 47, 110, 101, 116, 119, 111, 114, 107, 83, 101, 99, 117, 114, 105, 116, 121, 71, 114, 111, 117, 112, 115, 47, 112, 114, 105, 118, 97, 116, 101, 45, 110, 115, 103, 34, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]), pad([34, 47, 115, 117, 98, 115, 99, 114, 105, 112, 116, 105, 111, 110, 115, 47, 99, 99, 99, 99, 99, 99, 99, 99, 45, 49, 49, 49, 49, 45, 50, 50, 50, 50, 45, 51, 51, 51, 51, 45, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 47, 114, 101, 115, 111, 117, 114, 99, 101, 71, 114, 111, 117, 112, 115, 47, 112, 114, 105, 118, 97, 116, 101, 45, 103, 114, 111, 117, 112, 47, 112, 114, 111, 118, 105, 100, 101, 114, 115, 47, 77, 105, 99, 114, 111, 115, 111, 102, 116, 46, 78, 101, 116, 119, 111, 114, 107, 47, 110, 101, 116, 119, 111, 114, 107, 83, 101, 99, 117, 114, 105, 116, 121, 71, 114, 111, 117, 112, 115, 47, 112, 114, 105, 118, 97, 116, 101, 45, 110, 115, 103, 47, 115, 101, 99, 117, 114, 105, 116, 121, 82, 117, 108, 101, 115, 47, 112, 114, 105, 118, 97, 116, 101, 45, 114, 117, 108, 101, 34, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4])],
        correlations: [pad([34, 102, 102, 102, 102, 102, 102, 102, 102, 45, 49, 49, 49, 49, 45, 50, 50, 50, 50, 45, 51, 51, 51, 51, 45, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 34, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2]), pad([34, 102, 102, 102, 102, 102, 102, 102, 102, 45, 49, 49, 49, 49, 45, 50, 50, 50, 50, 45, 51, 51, 51, 51, 45, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 52, 34, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5])],
        timestamp: pad([34, 50, 48, 50, 54, 45, 49, 48, 45, 50, 57, 84, 48, 56, 58, 48, 48, 58, 48, 48, 90, 34, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3]),
    }
}

#[test]
fn authenticated_arg_activity_link() { let f = fixture(); main(f.hashes, f.lengths, CUTOFF, f.resources, f.correlations, f.timestamp); }

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_changed_target_hash() { let mut f = fixture(); f.hashes[0][0] = f.hashes[0][0] ^ 1; main(f.hashes, f.lengths, CUTOFF, f.resources, f.correlations, f.timestamp); }

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_changed_activity_opening() { let mut f = fixture(); f.resources[1][1] = 120; main(f.hashes, f.lengths, CUTOFF, f.resources, f.correlations, f.timestamp); }

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_changed_correlation_opening() { let mut f = fixture(); f.correlations[0][1] = 97; main(f.hashes, f.lengths, CUTOFF, f.resources, f.correlations, f.timestamp); }

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_changed_time_opening() { let mut f = fixture(); f.timestamp[1] = 49; main(f.hashes, f.lengths, CUTOFF, f.resources, f.correlations, f.timestamp); }

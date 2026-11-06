use super::{action, classify_keys};
global ACTOR: [u8; 36] = "11111111-1111-1111-1111-111111111111".as_bytes();
global TENANT: [u8; 36] = "22222222-2222-2222-2222-222222222222".as_bytes();
global SUBSCRIPTION: [u8; 36] = "66666666-6666-6666-6666-666666666666".as_bytes();
global CUTOFF: u64 = 1793232000000;

#[test]
fn long_claim_keys_do_not_alias_at_limb_boundaries() {
    let body = "{\"http://schemas.microsoft.com/identity/claims/objectidentifier\":1,\"http://schemas.microsoft.com/identity/claims/objectidentifiex\":2,\"http://schemas.microsoft.com/identity/claims/objectidentifierX\":3,\"http://schemas.microsoft.com/identity/claims/tenantid\":4,\"http://schemas.microsoft.com/identity/claims/tenantix\":5}".as_bytes();
    let parsed: source::json::Json<16> = source::json::parse_ascii_keys(body, body.len());
    let fields = classify_keys(body, body.len(), parsed);
    assert(fields[2] == 12);
    assert((fields[4] == 0) & (fields[6] == 0));
    assert(fields[8] == 13);
    assert(fields[10] == 0);
}

fn fixture(duplicate: bool) -> ([u8; 2048], u32) {
    let row = "{\"claims\":{\"http://schemas.microsoft.com/identity/claims/objectidentifier\":\"11111111-1111-1111-1111-111111111111\",\"http://schemas.microsoft.com/identity/claims/tenantid\":\"22222222-2222-2222-2222-222222222222\"},\"eventDataId\":\"33333333-3333-3333-3333-333333333333\",\"eventName\":{\"value\":\"EndRequest\"},\"eventTimestamp\":\"2026-10-28T00:00:00Z\",\"operationId\":\"44444444-4444-4444-4444-444444444444\",\"operationName\":{\"value\":\"Microsoft.Network/networkSecurityGroups/securityRules/write\"},\"status\":{\"value\":\"Succeeded\"},\"correlationId\":\"55555555-5555-5555-5555-555555555555\",\"resourceId\":\"/subscriptions/66666666-6666-6666-6666-666666666666/resourceGroups/test/providers/Microsoft.Network/networkSecurityGroups/test/securityRules/test\",\"subscriptionId\":\"66666666-6666-6666-6666-666666666666\"}".as_bytes();
    let mut body = [0u8; 2048];
    let prefix = "{\"value\":[".as_bytes();
    for i in 0..prefix.len() { body[i] = prefix[i]; }
    for i in 0..row.len() { body[prefix.len() + i] = row[i]; }
    let mut len = prefix.len() + row.len();
    if duplicate {
        body[len] = 44; len += 1;
        for i in 0..row.len() { body[len + i] = row[i]; }
        len += row.len();
    }
    body[len] = 93; body[len + 1] = 125;
    (body, len + 2)
}
fn replace<let K: u32>(mut body: [u8; 2048], len: u32, from: [u8; K], to: [u8; K], last: bool) -> [u8; 2048] {
    let mut at = 2048;
    for i in 0..2048 {
        if i + K <= len {
            let mut same = true;
            for j in 0..K { same = same & (body[i + j] == from[j]); }
            if same & (last | (at == 2048)) { at = i; }
        }
    }
    assert(at < 2048, "Test mutation missing");
    for i in 0..K { body[at + i] = to[i]; }
    body
}
#[test]
fn accepts_success_and_identical_duplicate_event() {
    let (body, len) = fixture(true);
    let result = action::<2048, 128, 2>(body, len, 0, ACTOR, TENANT, SUBSCRIPTION, CUTOFF);
    assert(!result.deleted);
    assert(result.correlation == "55555555-5555-5555-5555-555555555555".as_bytes());
}

#[test]
fn complete_activity_parse_cost_probe() {
    let (body, len) = fixture(true);
    let parsed: source::json::Json<128> = source::json::parse_ascii_keys(body, len);
    assert(parsed.count == 65);
}
#[test(should_fail_with = "Wrong Activity actor")]
fn rejects_other_actor() {
    let (body, len) = fixture(false);
    let _ = action::<2048, 128, 2>(body, len, 0, TENANT, TENANT, SUBSCRIPTION, CUTOFF);
}
#[test(should_fail_with = "Wrong Activity tenant")]
fn rejects_other_tenant() {
    let (body, len) = fixture(false);
    let _ = action::<2048, 128, 2>(body, len, 0, ACTOR, ACTOR, SUBSCRIPTION, CUTOFF);
}
#[test(should_fail_with = "Activity did not succeed")]
fn rejects_failed_action() {
    let (body, len) = fixture(false);
    let changed = replace(body, len, "Succeeded".as_bytes(), "Cancelled".as_bytes(), false);
    let _ = action::<2048, 128, 2>(changed, len, 0, ACTOR, TENANT, SUBSCRIPTION, CUTOFF);
}
#[test(should_fail_with = "Ambiguous Activity terminal outcome")]
fn rejects_conflicting_same_operation_terminal() {
    let (body, len) = fixture(true);
    let changed = replace(body, len, "Succeeded".as_bytes(), "Cancelled".as_bytes(), true);
    let _ = action::<2048, 128, 2>(changed, len, 0, ACTOR, TENANT, SUBSCRIPTION, CUTOFF);
}
#[test]
fn different_operation_failure_cannot_cancel_selected_success() {
    let (body, len) = fixture(true);
    let changed = replace(body, len, "Succeeded".as_bytes(), "Cancelled".as_bytes(), true);
    let changed = replace(changed, len, "33333333-3333-3333-3333-333333333333".as_bytes(), "77777777-7777-7777-7777-777777777777".as_bytes(), true);
    let changed = replace(changed, len, "44444444-4444-4444-4444-444444444444".as_bytes(), "88888888-8888-8888-8888-888888888888".as_bytes(), true);
    let result = action::<2048, 128, 2>(changed, len, 0, ACTOR, TENANT, SUBSCRIPTION, CUTOFF);
    assert(!result.deleted);
}
#[test]
fn accepts_exact_fourteen_day_boundary() {
    let (body, len) = fixture(false);
    let _ = action::<2048, 128, 2>(body, len, 0, ACTOR, TENANT, SUBSCRIPTION, CUTOFF + 13 * 86400000);
}
#[test(should_fail_with = "Timestamp before window")]
fn rejects_one_millisecond_before_window() {
    let (body, len) = fixture(false);
    let _ = action::<2048, 128, 2>(body, len, 0, ACTOR, TENANT, SUBSCRIPTION, CUTOFF + 13 * 86400000 + 1);
}
#[test(should_fail_with = "Unsupported Activity operation")]
fn rejects_other_operation() {
    let (body, len) = fixture(false);
    let changed = replace(body, len, "/write".as_bytes(), "/other".as_bytes(), false);
    let _ = action::<2048, 128, 2>(changed, len, 0, ACTOR, TENANT, SUBSCRIPTION, CUTOFF);
}
#[test(should_fail_with = "Unsupported escaped or non-ASCII selected field")]
fn escaped_keys_cannot_alias_selected_fields() {
    let body = "{\"value\":[],\"\\u0076alue\":[]}".as_bytes();
    let _ = action::<28, 16, 1>(body, body.len(), 0, ACTOR, TENANT, SUBSCRIPTION, CUTOFF);
}
#[test(should_fail_with = "Duplicate Azure field")]
fn duplicate_selected_field_is_rejected() {
    let (body, len) = fixture(false);
    let changed = replace(body, len, "\"eventDataId\"".as_bytes(), "\"operationId\"".as_bytes(), false);
    let _ = action::<2048, 128, 2>(changed, len, 0, ACTOR, TENANT, SUBSCRIPTION, CUTOFF);
}

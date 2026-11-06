use super::{Row, check, uuid, string};

fn pad<let N: u32, let M: u32>(value: [u8; M]) -> [u8; N] {
    assert(M <= N);
    let mut result = [0u8; N];
    for i in 0..M { result[i] = value[i]; }
    result
}

fn fixture() -> Row {
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/private-nsg/securityrules/private-rule".as_bytes();
    let operation = "Microsoft.Network/networkSecurityGroups/securityRules/write".as_bytes();
    Row {
        ids: ["aaaaaaaa-1111-2222-3333-444444444444".as_bytes(), "bbbbbbbb-1111-2222-3333-444444444444".as_bytes(),
            "cccccccc-1111-2222-3333-444444444444".as_bytes(), "dddddddd-1111-2222-3333-444444444444".as_bytes(),
            "eeeeeeee-1111-2222-3333-444444444444".as_bytes(), "ffffffff-1111-2222-3333-444444444444".as_bytes()],
        event: pad("EndRequest".as_bytes()), operation: pad(operation), status: pad("Succeeded".as_bytes()),
        timestamp: pad("2026-10-29T08:00:00Z".as_bytes()), resource: pad(resource),
        lengths: [10, operation.len(), 9, 20, resource.len()],
    }
}

global CUTOFF: u64 = 1793433600000;

#[test]
fn accepts_selected_and_matching_duplicate() { let row = fixture(); check::<0>(row, row, CUTOFF, 0); }

#[test]
fn accepts_started_row_of_same_operation() {
    let selected = fixture(); let mut other = selected;
    other.ids[3][0] = 97; other.event = pad("StartRequest".as_bytes()); other.lengths[0] = 12;
    other.status = pad("Started".as_bytes()); other.lengths[2] = 7;
    check::<0>(selected, other, CUTOFF, 0);
}

#[test]
fn accepts_distinct_operation_in_same_correlation() {
    let selected = fixture(); let mut other = selected;
    other.ids[3][0] = 97; other.ids[4][0] = 98; other.ids[0][0] = 99;
    other.status = pad("Failed".as_bytes()); other.lengths[2] = 6;
    check::<0>(selected, other, CUTOFF, 0);
}

#[test(should_fail_with = "Mixed Activity correlation")]
fn rejects_other_correlation() { let selected = fixture(); let mut other = selected; other.ids[5][0] = 97; check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Conflicting Activity event ID")]
fn rejects_same_event_different_operation() { let selected = fixture(); let mut other = selected; other.ids[4][0] = 97; check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Conflicting Activity actor")]
fn rejects_other_actor() { let selected = fixture(); let mut other = selected; other.ids[0][0] = 98; check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Conflicting Activity tenant")]
fn rejects_other_tenant() { let selected = fixture(); let mut other = selected; other.ids[1][0] = 97; check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Conflicting Activity subscription")]
fn rejects_other_subscription() { let selected = fixture(); let mut other = selected; other.ids[2][0] = 97; check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Ambiguous Activity terminal outcome")]
fn rejects_second_terminal_event() { let selected = fixture(); let mut other = selected; other.ids[3][0] = 97; check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Ambiguous Activity terminal outcome")]
fn rejects_failed_duplicate() { let selected = fixture(); let mut other = selected; other.status = pad("Failed".as_bytes()); other.lengths[2] = 6; check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Conflicting Activity event time")]
fn rejects_different_duplicate_time() { let selected = fixture(); let mut other = selected; other.timestamp[12] = 57; check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Conflicting Activity resource")]
fn rejects_other_resource() { let selected = fixture(); let mut other = selected; other.resource[other.lengths[4] - 1] = 97; check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Conflicting Activity operation")]
fn rejects_other_operation_name() { let selected = fixture(); let mut other = selected; let operation = "Microsoft.Network/networkSecurityGroups/securityRules/delete".as_bytes(); other.operation = pad(operation); other.lengths[1] = operation.len(); check::<0>(selected, other, CUTOFF, 0); }

#[test(should_fail_with = "Activity did not succeed")]
fn rejects_selected_failure() { let mut row = fixture(); row.status = pad("Failed".as_bytes()); row.lengths[2] = 6; check::<0>(row, row, CUTOFF, 0); }

#[test(should_fail_with = "Timestamp before window")]
fn rejects_old_event() { let mut row = fixture(); row.timestamp = pad("2026-10-01T08:00:00Z".as_bytes()); check::<0>(row, row, CUTOFF, 0); }

#[test(should_fail_with = "Wrong ARM rule path")]
fn rejects_resource_subscription_mismatch() { let mut row = fixture(); row.ids[2][0] = 97; check::<0>(row, row, CUTOFF, 0); }

#[test]
fn uuid_case_is_normalized() { assert(uuid("\"AAAAAAAA-1111-2222-3333-444444444444\"".as_bytes()) == "aaaaaaaa-1111-2222-3333-444444444444".as_bytes()); }

#[test(should_fail_with = "Invalid Activity UUID")]
fn rejects_non_hex_uuid() { let _ = uuid("\"gaaaaaaa-1111-2222-3333-444444444444\"".as_bytes()); }

#[test(should_fail_with = "Unsupported Activity string byte")]
fn rejects_hidden_quote_injection() { let _ = string::<3>("\"a\"b\"".as_bytes(), 5); }

struct Witness {
    hashes: [[u8; 32]; 11], lengths: [u32; 5], ids: [[u8; 54]; 6], event: [u8; 48],
    operation: [u8; 112], status: [u8; 48], timestamp: [u8; 48], resource: [u8; 530],
}

fn seal<let N: u32>(value: [u8; N], length: u32, salt: u8) -> ([u8; N + 18], [u8; 32]) {
    assert(length <= N);
    let mut opening = [0u8; N + 18]; opening[0] = 34;
    for i in 0..N { if i < length { opening[i + 1] = value[i]; } }
    opening[length + 1] = 34;
    for i in 0..16 { opening[length + 2 + i] = salt; }
    (opening, sha256::sha256_var(opening, length + 18))
}

fn witness(row: Row, salt: u8) -> Witness {
    let mut hashes = [[0u8; 32]; 11]; let mut ids = [[0u8; 54]; 6];
    for i in 0..6 { let (opening, hash) = seal(row.ids[i], 36, salt); ids[i] = opening; hashes[i] = hash; }
    let (event, event_hash) = seal(row.event, row.lengths[0], salt); hashes[6] = event_hash;
    let (operation, operation_hash) = seal(row.operation, row.lengths[1], salt); hashes[7] = operation_hash;
    let (status, status_hash) = seal(row.status, row.lengths[2], salt); hashes[8] = status_hash;
    let (timestamp, time_hash) = seal(row.timestamp, row.lengths[3], salt); hashes[9] = time_hash;
    let (resource, resource_hash) = seal(row.resource, row.lengths[4], salt); hashes[10] = resource_hash;
    let mut lengths = row.lengths;
    for i in 0..5 { lengths[i] += 2; }
    Witness { hashes, lengths, ids, event, operation, status, timestamp, resource }
}

fn verify(selected: Witness, other: Witness) {
    super::verify_rule([selected.hashes, other.hashes], [selected.lengths, other.lengths], CUTOFF,
        [selected.ids, other.ids], [selected.event, other.event], [selected.operation, other.operation],
        [selected.status, other.status], [selected.timestamp, other.timestamp], [selected.resource, other.resource]);
}

#[test]
fn authenticates_independently_blinded_complete_rows() {
    let selected = witness(fixture(), 17); let other = witness(fixture(), 23);
    assert(selected.hashes[0] != other.hashes[0]); verify(selected, other);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_modified_private_opening() {
    let selected = witness(fixture(), 17); let mut other = witness(fixture(), 23);
    other.resource[1] = 120; verify(selected, other);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_changed_public_hash() {
    let selected = witness(fixture(), 17); let mut other = witness(fixture(), 23);
    other.hashes[5][0] = other.hashes[5][0] ^ 1; verify(selected, other);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_changed_public_length() {
    let selected = witness(fixture(), 17); let mut other = witness(fixture(), 23);
    other.lengths[4] -= 1; verify(selected, other);
}

#[test(should_fail_with = "Ambiguous Activity terminal outcome")]
fn rejects_authenticated_conflicting_terminal() {
    let selected = witness(fixture(), 17); let mut other = fixture(); other.ids[3][0] = 97;
    verify(selected, witness(other, 23));
}

#[test(should_fail_with = "Unsupported Activity string byte")]
fn rejects_authenticated_field_injection() {
    let selected = witness(fixture(), 17); let mut other = fixture(); other.status[1] = 34;
    verify(selected, witness(other, 23));
}

#[test]
fn accepts_authenticated_delete_and_case_normalized_resource() {
    let mut row = fixture(); let operation = "Microsoft.Network/networkSecurityGroups/securityRules/delete".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    let selected = witness(row, 17); row.resource[1] = 83; row.ids[0][0] = 65;
    verify(selected, witness(row, 23));
}

fn verify_catalog(selected: Witness, other: Witness, profile_code: u8) {
    super::verify_catalog([selected.hashes, other.hashes], [selected.lengths, other.lengths], CUTOFF, profile_code,
        [selected.ids, other.ids], [selected.event, other.event], [selected.operation, other.operation],
        [selected.status, other.status], [selected.timestamp, other.timestamp], [selected.resource, other.resource]);
}

fn catalog_1() -> Row {
    let mut row = fixture();
    let operation = "Microsoft.Network/networkSecurityGroups/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/private-name".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len(); row
}

#[test]
fn catalog_1_authenticates_independent_blinders() { verify_catalog(witness(catalog_1(), 17), witness(catalog_1(), 23), 1); }

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_1_rejects_wrong_public_profile() { verify_catalog(witness(catalog_1(), 17), witness(catalog_1(), 23), 2); }

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_1_rejects_another_profiles_resource() {
    let mut row = catalog_1(); let other = catalog_2();
    row.resource = other.resource; row.lengths[4] = other.lengths[4];
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

fn catalog_2() -> Row {
    let mut row = fixture();
    let operation = "Microsoft.Compute/virtualMachines/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private-name".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len(); row
}

#[test]
fn catalog_2_authenticates_independent_blinders() { verify_catalog(witness(catalog_2(), 17), witness(catalog_2(), 23), 2); }

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_2_rejects_wrong_public_profile() { verify_catalog(witness(catalog_2(), 17), witness(catalog_2(), 23), 3); }

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_2_rejects_another_profiles_resource() {
    let mut row = catalog_2(); let other = catalog_3();
    row.resource = other.resource; row.lengths[4] = other.lengths[4];
    verify_catalog(witness(row, 17), witness(row, 23), 2);
}

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_2_rejects_delete() {
    let mut row = catalog_2(); let operation = "Microsoft.Compute/virtualMachines/delete".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    verify_catalog(witness(row, 17), witness(row, 23), 2);
}

fn catalog_3() -> Row {
    let mut row = fixture();
    let operation = "Microsoft.Web/sites/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-name".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len(); row
}

#[test]
fn catalog_3_authenticates_independent_blinders() { verify_catalog(witness(catalog_3(), 17), witness(catalog_3(), 23), 3); }

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_3_rejects_wrong_public_profile() { verify_catalog(witness(catalog_3(), 17), witness(catalog_3(), 23), 4); }

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_3_rejects_another_profiles_resource() {
    let mut row = catalog_3(); let other = catalog_4();
    row.resource = other.resource; row.lengths[4] = other.lengths[4];
    verify_catalog(witness(row, 17), witness(row, 23), 3);
}

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_3_rejects_delete() {
    let mut row = catalog_3(); let operation = "Microsoft.Web/sites/delete".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    verify_catalog(witness(row, 17), witness(row, 23), 3);
}

fn catalog_4() -> Row {
    let mut row = fixture();
    let operation = "Microsoft.ContainerService/managedClusters/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.containerservice/managedclusters/private-name".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len(); row
}

#[test]
fn catalog_4_authenticates_independent_blinders() { verify_catalog(witness(catalog_4(), 17), witness(catalog_4(), 23), 4); }

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_4_rejects_wrong_public_profile() { verify_catalog(witness(catalog_4(), 17), witness(catalog_4(), 23), 5); }

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_4_rejects_another_profiles_resource() {
    let mut row = catalog_4(); let other = catalog_5();
    row.resource = other.resource; row.lengths[4] = other.lengths[4];
    verify_catalog(witness(row, 17), witness(row, 23), 4);
}

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_4_rejects_delete() {
    let mut row = catalog_4(); let operation = "Microsoft.ContainerService/managedClusters/delete".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    verify_catalog(witness(row, 17), witness(row, 23), 4);
}

fn catalog_5() -> Row {
    let mut row = fixture();
    let operation = "Microsoft.Network/virtualNetworks/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/virtualnetworks/private-name".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len(); row
}

#[test]
fn catalog_5_authenticates_independent_blinders() { verify_catalog(witness(catalog_5(), 17), witness(catalog_5(), 23), 5); }

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_5_rejects_wrong_public_profile() { verify_catalog(witness(catalog_5(), 17), witness(catalog_5(), 23), 6); }

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_5_rejects_another_profiles_resource() {
    let mut row = catalog_5(); let other = catalog_6();
    row.resource = other.resource; row.lengths[4] = other.lengths[4];
    verify_catalog(witness(row, 17), witness(row, 23), 5);
}

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_5_rejects_delete() {
    let mut row = catalog_5(); let operation = "Microsoft.Network/virtualNetworks/delete".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    verify_catalog(witness(row, 17), witness(row, 23), 5);
}

fn catalog_6() -> Row {
    let mut row = fixture();
    let operation = "Microsoft.Storage/storageAccounts/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.storage/storageaccounts/private-name".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len(); row
}

#[test]
fn catalog_6_authenticates_independent_blinders() { verify_catalog(witness(catalog_6(), 17), witness(catalog_6(), 23), 6); }

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_6_rejects_wrong_public_profile() { verify_catalog(witness(catalog_6(), 17), witness(catalog_6(), 23), 7); }

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_6_rejects_another_profiles_resource() {
    let mut row = catalog_6(); let other = catalog_7();
    row.resource = other.resource; row.lengths[4] = other.lengths[4];
    verify_catalog(witness(row, 17), witness(row, 23), 6);
}

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_6_rejects_delete() {
    let mut row = catalog_6(); let operation = "Microsoft.Storage/storageAccounts/delete".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    verify_catalog(witness(row, 17), witness(row, 23), 6);
}

fn catalog_7() -> Row {
    let mut row = fixture();
    let operation = "Microsoft.KeyVault/vaults/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.keyvault/vaults/private-name".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len(); row
}

#[test]
fn catalog_7_authenticates_independent_blinders() { verify_catalog(witness(catalog_7(), 17), witness(catalog_7(), 23), 7); }

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_7_rejects_wrong_public_profile() { verify_catalog(witness(catalog_7(), 17), witness(catalog_7(), 23), 8); }

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_7_rejects_another_profiles_resource() {
    let mut row = catalog_7(); let other = catalog_8();
    row.resource = other.resource; row.lengths[4] = other.lengths[4];
    verify_catalog(witness(row, 17), witness(row, 23), 7);
}

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_7_rejects_delete() {
    let mut row = catalog_7(); let operation = "Microsoft.KeyVault/vaults/delete".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    verify_catalog(witness(row, 17), witness(row, 23), 7);
}

fn catalog_8() -> Row {
    let mut row = fixture();
    let operation = "Microsoft.Insights/metricAlerts/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.insights/metricalerts/private-name".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len(); row
}

#[test]
fn catalog_8_authenticates_independent_blinders() { verify_catalog(witness(catalog_8(), 17), witness(catalog_8(), 23), 8); }

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_8_rejects_wrong_public_profile() { verify_catalog(witness(catalog_8(), 17), witness(catalog_8(), 23), 1); }

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_8_rejects_another_profiles_resource() {
    let mut row = catalog_8(); let other = catalog_1();
    row.resource = other.resource; row.lengths[4] = other.lengths[4];
    verify_catalog(witness(row, 17), witness(row, 23), 8);
}

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_8_rejects_delete() {
    let mut row = catalog_8(); let operation = "Microsoft.Insights/metricAlerts/delete".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    verify_catalog(witness(row, 17), witness(row, 23), 8);
}

#[test]
fn catalog_parent_delete_normalizes_resource_case() {
    let mut row = catalog_1(); let operation = "Microsoft.Network/networkSecurityGroups/delete".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    let selected = witness(row, 17); row.resource[1] = 83;
    verify_catalog(selected, witness(row, 23), 1);
}

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_rejects_zero_profile() { let row = catalog_1(); check::<1>(row, row, CUTOFF, 0); }

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_rejects_unknown_profile() { let row = catalog_1(); check::<1>(row, row, CUTOFF, 255); }

#[test(should_fail_with = "Unsupported Activity operation")]
fn old_rule_profile_rejects_parent() { let row = catalog_1(); check::<0>(row, row, CUTOFF, 0); }

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_rejects_old_rule_path() { let row = fixture(); check::<1>(row, row, CUTOFF, 1); }

#[test]
fn catalog_accepts_selected_and_matching_duplicate() { let row = catalog_1(); check::<1>(row, row, CUTOFF, 1); }

#[test]
fn catalog_accepts_started_row_of_same_operation() {
    let selected = catalog_1(); let mut other = selected;
    other.ids[3][0] = 97; other.event = pad("StartRequest".as_bytes()); other.lengths[0] = 12;
    other.status = pad("Started".as_bytes()); other.lengths[2] = 7;
    check::<1>(selected, other, CUTOFF, 1);
}

#[test]
fn catalog_accepts_distinct_operation_in_same_correlation() {
    let selected = catalog_1(); let mut other = selected;
    other.ids[3][0] = 97; other.ids[4][0] = 98; other.ids[0][0] = 99;
    other.status = pad("Failed".as_bytes()); other.lengths[2] = 6;
    check::<1>(selected, other, CUTOFF, 1);
}

#[test(should_fail_with = "Mixed Activity correlation")]
fn catalog_rejects_other_correlation() { let selected = catalog_1(); let mut other = selected; other.ids[5][0] = 97; check::<1>(selected, other, CUTOFF, 1); }

#[test(should_fail_with = "Conflicting Activity event ID")]
fn catalog_rejects_same_event_different_operation() { let selected = catalog_1(); let mut other = selected; other.ids[4][0] = 97; check::<1>(selected, other, CUTOFF, 1); }

#[test(should_fail_with = "Conflicting Activity actor")]
fn catalog_rejects_other_actor() { let selected = catalog_1(); let mut other = selected; other.ids[0][0] = 98; check::<1>(selected, other, CUTOFF, 1); }

#[test(should_fail_with = "Conflicting Activity tenant")]
fn catalog_rejects_other_tenant() { let selected = catalog_1(); let mut other = selected; other.ids[1][0] = 97; check::<1>(selected, other, CUTOFF, 1); }

#[test(should_fail_with = "Conflicting Activity subscription")]
fn catalog_rejects_other_subscription() { let selected = catalog_1(); let mut other = selected; other.ids[2][0] = 97; check::<1>(selected, other, CUTOFF, 1); }

#[test(should_fail_with = "Ambiguous Activity terminal outcome")]
fn catalog_rejects_second_terminal_event() { let selected = catalog_1(); let mut other = selected; other.ids[3][0] = 97; check::<1>(selected, other, CUTOFF, 1); }

#[test(should_fail_with = "Ambiguous Activity terminal outcome")]
fn catalog_rejects_failed_duplicate() { let selected = catalog_1(); let mut other = selected; other.status = pad("Failed".as_bytes()); other.lengths[2] = 6; check::<1>(selected, other, CUTOFF, 1); }

#[test(should_fail_with = "Conflicting Activity event time")]
fn catalog_rejects_different_duplicate_time() { let selected = catalog_1(); let mut other = selected; other.timestamp[12] = 57; check::<1>(selected, other, CUTOFF, 1); }

#[test(should_fail_with = "Conflicting Activity resource")]
fn catalog_rejects_other_resource() { let selected = catalog_1(); let mut other = selected; other.resource[other.lengths[4] - 1] = 97; check::<1>(selected, other, CUTOFF, 1); }

#[test(should_fail_with = "Activity did not succeed")]
fn catalog_rejects_selected_failure() { let mut row = catalog_1(); row.status = pad("Failed".as_bytes()); row.lengths[2] = 6; check::<1>(row, row, CUTOFF, 1); }

#[test(should_fail_with = "Timestamp before window")]
fn catalog_rejects_old_event() { let mut row = catalog_1(); row.timestamp = pad("2026-10-01T08:00:00Z".as_bytes()); check::<1>(row, row, CUTOFF, 1); }

#[test(should_fail_with = "Wrong catalog ARM scope")]
fn catalog_rejects_resource_subscription_mismatch() { let mut row = catalog_1(); row.ids[2][0] = 97; check::<1>(row, row, CUTOFF, 1); }

#[test]
fn catalog_authenticates_independently_blinded_complete_rows() {
    let selected = witness(catalog_1(), 17); let other = witness(catalog_1(), 23);
    assert(selected.hashes[0] != other.hashes[0]); verify_catalog(selected, other, 1);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn catalog_rejects_modified_private_opening() {
    let selected = witness(catalog_1(), 17); let mut other = witness(catalog_1(), 23);
    other.resource[1] = 120; verify_catalog(selected, other, 1);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn catalog_rejects_changed_public_hash() {
    let selected = witness(catalog_1(), 17); let mut other = witness(catalog_1(), 23);
    other.hashes[5][0] = other.hashes[5][0] ^ 1; verify_catalog(selected, other, 1);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn catalog_rejects_changed_public_length() {
    let selected = witness(catalog_1(), 17); let mut other = witness(catalog_1(), 23);
    other.lengths[4] -= 1; verify_catalog(selected, other, 1);
}

#[test(should_fail_with = "Ambiguous Activity terminal outcome")]
fn catalog_rejects_authenticated_conflicting_terminal() {
    let selected = witness(catalog_1(), 17); let mut other = catalog_1(); other.ids[3][0] = 97;
    verify_catalog(selected, witness(other, 23), 1);
}

#[test(should_fail_with = "Unsupported Activity string byte")]
fn catalog_rejects_authenticated_field_injection() {
    let selected = witness(catalog_1(), 17); let mut other = catalog_1(); other.status[1] = 34;
    verify_catalog(selected, witness(other, 23), 1);
}

#[test(should_fail_with = "Empty ARM path segment")]
fn catalog_rejects_empty_name() {
    let mut row = catalog_1(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/".as_bytes();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Unsupported ARM name segment")]
fn catalog_rejects_dot_name() {
    let mut row = catalog_1(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/.".as_bytes();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Unsupported ARM name segment")]
fn catalog_rejects_dotdot_name() {
    let mut row = catalog_1(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/..".as_bytes();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_rejects_child_path() {
    let mut row = catalog_1(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/private-name/child/name".as_bytes();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Empty ARM path segment")]
fn catalog_rejects_trailing_slash() {
    let mut row = catalog_1(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/private-name/".as_bytes();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Unsupported ARM name")]
fn catalog_rejects_percent_name() {
    let mut row = catalog_1(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.network/networksecuritygroups/private%2fname".as_bytes();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Unsupported ARM name segment")]
fn catalog_rejects_dot_group() {
    let mut row = catalog_1(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/./providers/microsoft.network/networksecuritygroups/private-name".as_bytes();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Unsupported ARM name segment")]
fn catalog_rejects_dotdot_group() {
    let mut row = catalog_1(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/../providers/microsoft.network/networksecuritygroups/private-name".as_bytes();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}


#[test]
fn rest_sql() {
    let mut row = fixture(); let operation = "Microsoft.Sql/servers/databases/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/databases/private-db".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 9);
}

#[test]
fn rest_pipeline() {
    let mut row = fixture(); let operation = "Microsoft.DataFactory/factories/pipelines/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.datafactory/factories/private-factory/pipelines/private-pipeline".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 10);
}

#[test]
fn rest_group_write() {
    let mut row = fixture(); let operation = "Microsoft.Resources/subscriptions/resourceGroups/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 11);
}

#[test]
fn rest_group_delete() {
    let mut row = fixture(); let operation = "Microsoft.Resources/subscriptions/resourceGroups/delete".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 11);
}

#[test]
fn rest_rg_deployment() {
    let mut row = fixture(); let operation = "Microsoft.Resources/deployments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.resources/deployments/private-deployment".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 12);
}

#[test]
fn rest_subscription_deployment() {
    let mut row = fixture(); let operation = "Microsoft.Resources/deployments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.resources/deployments/private-deployment".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 12);
}

#[test]
fn rest_subscription_role() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test]
fn rest_rg_role() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test]
fn rest_resource_role() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private-vm/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test]
fn rest_nested_resource_role() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/databases/private-db/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test]
fn rest_extension_resource_role() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private-vm/providers/microsoft.insights/diagnosticsettings/private-diagnostic/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test]
fn rest_subscription_resource_role() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.resources/deployments/private-deployment/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test]
fn rest_reserved_name_role() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/providers/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_sql_missing_parent() {
    let mut row = fixture(); let operation = "Microsoft.Sql/servers/databases/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.sql/databases/private-db".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 9);
}

#[test(should_fail)]
fn rest_sql_wrong_child() {
    let mut row = fixture(); let operation = "Microsoft.Sql/servers/databases/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/elasticpools/private-db".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 9);
}

#[test(should_fail)]
fn rest_pipeline_wrong_provider() {
    let mut row = fixture(); let operation = "Microsoft.DataFactory/factories/pipelines/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.sql/factories/private-factory/pipelines/private-pipeline".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 10);
}

#[test(should_fail)]
fn rest_group_action_on_resource() {
    let mut row = fixture(); let operation = "Microsoft.Resources/subscriptions/resourceGroups/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/databases/private-db".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 11);
}

#[test(should_fail)]
fn rest_deployment_wrong_provider() {
    let mut row = fixture(); let operation = "Microsoft.Resources/deployments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.apicenter/deployments/private-deployment".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 12);
}

#[test(should_fail)]
fn rest_foreign_subscription() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/dddddddd-1111-2222-3333-444444444444/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_non_guid_assignment() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.authorization/roleassignments/private-assignment".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_bad_guid_assignment() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.authorization/roleassignments/gddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_missing_type() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_missing_name() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_bad_namespace() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft..compute/virtualmachines/private-vm/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_missing_namespace() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/virtualmachines/private-vm/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_incomplete_extension() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private-vm/providers/microsoft.insights/diagnosticsettings/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_role_suffix_child() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444/child/name".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_wrong_role_suffix() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.authorization/roledefinitions/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_management_group() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/providers/microsoft.management/managementgroups/private-group/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_dot_parent() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/../providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_unpaired_scope_prefix() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/arbitrary/prefix/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail)]
fn rest_too_many_segments() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test]
fn slot_swap_accepts_source_slot_operation() {
    let mut row = fixture(); let operation = "Microsoft.Web/sites/slots/slotsswap/action".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slots/private-slot".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn rest_sql_rejects_wrong_public_code() {
    let mut row = fixture(); let operation = "Microsoft.Sql/servers/databases/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/databases/private-db".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn rest_pipeline_rejects_wrong_public_code() {
    let mut row = fixture(); let operation = "Microsoft.DataFactory/factories/pipelines/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.datafactory/factories/private-factory/pipelines/private-pipeline".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn rest_group_write_rejects_wrong_public_code() {
    let mut row = fixture(); let operation = "Microsoft.Resources/subscriptions/resourceGroups/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn rest_rg_deployment_rejects_wrong_public_code() {
    let mut row = fixture(); let operation = "Microsoft.Resources/deployments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.resources/deployments/private-deployment".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn rest_subscription_role_rejects_wrong_public_code() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes(); let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 1);
}

#[test(should_fail_with = "Invalid ARM provider namespace")]
fn scan_rejects_namespace_first_digit() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/1microsoft.compute/virtualmachines/private-vm/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail_with = "Invalid ARM provider namespace")]
fn scan_rejects_namespace_last_dot() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute./virtualmachines/private-vm/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail_with = "Invalid ARM provider namespace")]
fn scan_rejects_namespace_last_underscore() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute_/virtualmachines/private-vm/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail_with = "Invalid ARM provider namespace")]
fn scan_rejects_second_namespace_no_dot() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private.vm/providers/nodot/diagnosticsettings/private-setting/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail_with = "Invalid ARM provider namespace")]
fn scan_rejects_second_namespace_first_digit() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private-vm/providers/1microsoft.insights/diagnosticsettings/private-setting/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail_with = "Invalid ARM provider namespace")]
fn scan_rejects_second_namespace_adjacent_dots() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/virtualmachines/private-vm/providers/microsoft..insights/diagnosticsettings/private-setting/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

#[test(should_fail_with = "Missing ARM resource type")]
fn scan_rejects_providers_in_type_position() {
    let mut row = fixture(); let operation = "Microsoft.Authorization/roleAssignments/write".as_bytes();
    let resource = "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.compute/providers/private-name/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    verify_catalog(witness(row, 17), witness(row, 23), 13);
}

// Additional catalog operation cases.

#[test]
fn tokenizer_variable_ends_at_capacity() {
    let mut value = [0u8; 512];
    for i in 0..32 { value[2 * i] = 47; value[2 * i + 1] = 97; }
    let (starts, ends, count) = super::tokenize::<32, 1>(value, 64);
    assert(count == 32);
    for i in 0..32 {
        assert(starts[i] == 2 * i + 1);
        assert(ends[i] == 2 * i + 2);
    }
}

#[test]
fn tokenizer_variable_ends_zero_unused() {
    let mut value: [u8; 512] = pad("/ab/cde".as_bytes());
    value[7] = 47; value[511] = 47;
    let (starts, ends, count) = super::tokenize::<32, 1>(value, 7);
    assert(count == 2);
    assert((starts[0] == 1) & (ends[0] == 3));
    assert((starts[1] == 4) & (ends[1] == 7));
    for i in 2..32 { assert((starts[i] == 0) & (ends[i] == 0)); }
}

fn operation_case(mut row: Row, mixed: bool) -> Row {
    for i in 0..94 {
        let c = super::lower(row.operation[i]);
        row.operation[i] = if mixed & (i % 2 == 0) & (c >= 97) & (c <= 122) { c - 32 } else { c };
    }
    row
}

fn catalog_case_pair(row: Row, code: u8) {
    let lower = operation_case(row, false); let mixed = operation_case(row, true);
    check::<1>(lower, mixed, CUTOFF, code);
    verify_catalog(witness(mixed, 17), witness(lower, 23), code);
}

fn catalog_case_row<let O: u32, let R: u32>(operation: [u8; O], resource: [u8; R]) -> Row {
    let mut row = fixture();
    row.operation = pad(operation); row.lengths[1] = O;
    row.resource = pad(resource); row.lengths[4] = R; row
}

#[test]
fn catalog_case_01_lower_and_mixed() { catalog_case_pair(catalog_1(), 1); }
#[test]
fn catalog_case_02_lower_and_mixed() { catalog_case_pair(catalog_2(), 2); }
#[test]
fn catalog_case_03_lower_and_mixed() { catalog_case_pair(catalog_3(), 3); }
#[test]
fn catalog_case_04_lower_and_mixed() { catalog_case_pair(catalog_4(), 4); }
#[test]
fn catalog_case_05_lower_and_mixed() { catalog_case_pair(catalog_5(), 5); }
#[test]
fn catalog_case_06_lower_and_mixed() { catalog_case_pair(catalog_6(), 6); }
#[test]
fn catalog_case_07_lower_and_mixed() { catalog_case_pair(catalog_7(), 7); }
#[test]
fn catalog_case_08_lower_and_mixed() { catalog_case_pair(catalog_8(), 8); }

#[test]
fn catalog_case_09_lower_and_mixed() {
    catalog_case_pair(catalog_case_row("Microsoft.Sql/servers/databases/write".as_bytes(),
        "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.sql/servers/private-server/databases/private-db".as_bytes()), 9);
}
#[test]
fn catalog_case_10_lower_and_mixed() {
    catalog_case_pair(catalog_case_row("Microsoft.DataFactory/factories/pipelines/write".as_bytes(),
        "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.datafactory/factories/private-factory/pipelines/private-pipeline".as_bytes()), 10);
}
#[test]
fn catalog_case_11_lower_and_mixed() {
    catalog_case_pair(catalog_case_row("Microsoft.Resources/subscriptions/resourceGroups/write".as_bytes(),
        "/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group".as_bytes()), 11);
}
#[test]
fn catalog_case_12_lower_and_mixed() {
    catalog_case_pair(catalog_case_row("Microsoft.Resources/deployments/write".as_bytes(),
        "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.resources/deployments/private-deployment".as_bytes()), 12);
}
#[test]
fn catalog_case_13_lower_and_mixed() {
    catalog_case_pair(catalog_case_row("Microsoft.Authorization/roleAssignments/write".as_bytes(),
        "/subscriptions/cccccccc-1111-2222-3333-444444444444/providers/microsoft.authorization/roleassignments/dddddddd-1111-2222-3333-444444444444".as_bytes()), 13);
}

#[test(should_fail_with = "Conflicting Activity operation")]
fn catalog_case_rejects_altered_same_operation() {
    let selected = operation_case(catalog_2(), false); let mut other = operation_case(catalog_2(), true);
    other.operation[other.lengths[1] - 1] = 120;
    verify_catalog(witness(selected, 17), witness(other, 23), 2);
}

#[test(should_fail_with = "Unsupported catalog operation/resource pair")]
fn catalog_case_rejects_wrong_suffix() {
    let mut row = operation_case(catalog_2(), true);
    row.operation[row.lengths[1]] = 115; row.lengths[1] += 1;
    verify_catalog(witness(row, 17), witness(row, 23), 2);
}

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn catalog_case_rejects_wrong_profile() {
    let row = operation_case(catalog_2(), false);
    verify_catalog(witness(row, 17), witness(row, 23), 3);
}

#[test(should_fail_with = "Unsupported Activity string byte")]
fn catalog_case_rejects_unicode_kelvin_lookalike() {
    let mut row = catalog_7(); let original = row.operation;
    // Replace ASCII K at offset ten with UTF-8 U+212A, preserving valid UTF-8.
    for i in 13..94 { if i < row.lengths[1] + 2 { row.operation[i] = original[i - 2]; } }
    row.operation[10] = 226; row.operation[11] = 132; row.operation[12] = 170;
    row.lengths[1] += 2;
    verify_catalog(witness(row, 17), witness(row, 23), 7);
}

#[test(should_fail_with = "Unsupported Activity operation")]
fn catalog_case_keeps_rule_operation_policy_unchanged() {
    let row = operation_case(fixture(), false);
    verify(witness(row, 17), witness(row, 23));
}

// Operation-only profile: ownership grammar never identifies either swap endpoint.
fn swap_row<let N: u32>(resource: [u8; N]) -> Row {
    let mut row = fixture();
    let operation = "Microsoft.Web/sites/slots/slotsswap/action".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    row.resource = pad(resource); row.lengths[4] = resource.len();
    row
}

#[test]
fn slot_swap_site() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test]
fn slot_swap_action_route() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slots/private-slot/slotsswap".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test]
fn slot_swap_site_action_route() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slotsswap".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test]
fn slot_swap_child_scope() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slots/private-slot/config/web".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test]
fn slot_swap_provider_as_name() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slots/providers".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_wrong_provider() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.sql/sites/private-site".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_wrong_type() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/slots/private-site".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_cross_subscription() {
    let row = swap_row("/subscriptions/aaaaaaaa-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_escape_extension() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/providers/microsoft.sql/servers/private".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_dot() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slots/../".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_dangling_child() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slots".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_wrong_action_suffix() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slots/private-slot/restart".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_trailing_slash() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_empty_segment() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/slots//private".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn slot_swap_rejects_web_app_code() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 3);
}

#[test(should_fail_with = "Authenticated catalog profile mismatch")]
fn web_app_rejects_swap_code() {
    let mut row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    let operation = "Microsoft.Web/sites/write".as_bytes();
    row.operation = pad(operation); row.lengths[1] = operation.len();
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail_with = "Ambiguous Activity terminal outcome")]
fn slot_swap_rejects_conflicting_terminal() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    let mut other = row; other.status = pad("Failed".as_bytes()); other.lengths[2] = 6;
    verify_catalog(witness(row, 17), witness(other, 23), 14);
}

#[test(should_fail_with = "Conflicting Activity actor")]
fn slot_swap_rejects_conflicting_actor() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    let mut other = row; other.ids[0][0] = 98;
    verify_catalog(witness(row, 17), witness(other, 23), 14);
}

#[test(should_fail_with = "Mixed Activity correlation")]
fn slot_swap_rejects_mixed_correlation() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    let mut other = row; other.ids[5][0] = 97;
    verify_catalog(witness(row, 17), witness(other, 23), 14);
}

#[test(should_fail_with = "Timestamp before window")]
fn slot_swap_rejects_old_event() {
    let mut row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    row.timestamp = pad("2026-10-01T08:00:00Z".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test]
fn slot_swap_at_segment_bound() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail)]
fn slot_swap_over_segment_bound() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b/a/b".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test]
fn slot_swap_accepts_uppercase_authenticated_operation() {
    let mut row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    row.operation = pad("MICROSOFT.WEB/SITES/SLOTS/SLOTSSWAP/ACTION".as_bytes());
    verify_catalog(witness(row, 17), witness(row, 23), 14);
}

#[test(should_fail_with = "Conflicting Activity resource")]
fn slot_swap_rejects_same_operation_different_site() {
    let row = swap_row("/subscriptions/cccccccc-1111-2222-3333-444444444444/resourcegroups/private-group/providers/microsoft.web/sites/private-site".as_bytes());
    let mut other = row; other.resource[row.lengths[4] - 1] = 98;
    verify_catalog(witness(row, 17), witness(other, 23), 14);
}

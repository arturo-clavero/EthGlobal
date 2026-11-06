mod tests;

struct Row {
    ids: [[u8; 36]; 6],
    event: [u8; 30],
    operation: [u8; 94],
    status: [u8; 30],
    timestamp: [u8; 30],
    resource: [u8; 512],
    lengths: [u32; 5],
}

fn lower(c: u8) -> u8 { if (c >= 65) & (c <= 90) { c + 32 } else { c } }

fn string<let N: u32>(bytes: [u8; N + 2], length: u32) -> ([u8; N], u32) {
    assert((length >= 2) & (length <= N + 2), "Invalid Activity string length");
    assert((bytes[0] == 34) & (bytes[length - 1] == 34), "Expected quoted Activity string");
    let mut value = [0u8; N];
    for i in 0..N {
        if i < length - 2 {
            let c = bytes[i + 1];
            assert((c >= 32) & (c <= 126) & (c != 34) & (c != 92), "Unsupported Activity string byte");
            value[i] = c;
        }
    }
    (value, length - 2)
}

fn uuid(bytes: [u8; 38]) -> [u8; 36] {
    let (mut value, _) = string::<36>(bytes, 38);
    for i in 0..36 {
        let c = lower(value[i]);
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) { assert(c == 45, "Invalid Activity UUID"); }
        else { assert(((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)), "Invalid Activity UUID"); }
        value[i] = c;
    }
    value
}

fn equal<let N: u32, let M: u32>(value: [u8; N], length: u32, expected: [u8; M]) -> bool {
    assert(M <= N);
    let mut result = length == M;
    for i in 0..M { result = result & (value[i] == expected[i]); }
    result
}

fn segment<let M: u32>(value: [u8; 512], start: u32, end: u32, expected: [u8; M]) -> bool {
    let mut result = end - start == M;
    for i in 0..M {
        if start + i < 512 { result = result & (value[start + i] == expected[i]); }
        else { result = false; }
    }
    result
}

fn tokenize<let CAP: u32, let VARIABLE: u32>(value: [u8; 512], length: u32) -> ([u32; CAP], [u32; CAP], u32) {
    assert((length > 1) & (value[0] == 47), "Expected ARM resource path");
    let mut starts = [0u32; CAP];
    let mut ends = [0u32; CAP];
    let mut count = 0;
    for i in 0..512 {
        if i < length {
            let c = value[i];
            if c == 47 {
                if VARIABLE == 0 { if count > 0 { ends[count - 1] = i; } }
                assert(count < CAP, "Wrong ARM rule path");
                starts[count] = i + 1; count += 1;
            } else {
                assert(((c >= 97) & (c <= 122)) | ((c >= 48) & (c <= 57)) | (c == 45) | (c == 46) | (c == 95) | (c == 40) | (c == 41), "Unsupported ARM name");
            }
        }
    }
    if VARIABLE == 0 {
        assert(count == CAP, "Wrong ARM rule path"); ends[CAP - 1] = length;
        for i in 0..CAP { assert(starts[i] < ends[i], "Empty ARM path segment"); }
    } else {
        assert(count >= 2, "Wrong catalog ARM scope");
        // Each next segment starts immediately after the preceding separator.
        for i in 0..CAP - 1 {
            if i < count { ends[i] = if i + 1 < count { starts[i + 1] - 1 } else { length }; }
        }
        if count == CAP { ends[CAP - 1] = length; }
        for i in 0..CAP { if i < count { assert(starts[i] < ends[i], "Empty ARM path segment"); } }
    }
    (starts, ends, count)
}

fn resource(value: [u8; 512], length: u32, subscription: [u8; 36]) {
    let (starts, ends, _) = tokenize::<10, 0>(value, length);
    assert(segment(value, starts[0], ends[0], "subscriptions".as_bytes()) &
        segment(value, starts[1], ends[1], subscription) &
        segment(value, starts[2], ends[2], "resourcegroups".as_bytes()) &
        segment(value, starts[4], ends[4], "providers".as_bytes()) &
        segment(value, starts[5], ends[5], "microsoft.network".as_bytes()) &
        segment(value, starts[6], ends[6], "networksecuritygroups".as_bytes()) &
        segment(value, starts[8], ends[8], "securityrules".as_bytes()), "Wrong ARM rule path");
}

// Role-assignment scope grammar is confined to this selected-subscription profile.
// Provider namespaces use a conservative ASCII dotted-identifier subset.
// The scope FSM derives marked segments from the authenticated tokenizer output.
// Walk those same nonempty ordered intervals once, following activity.nr's cursor pattern.
fn namespaces(value: [u8; 512], starts: [u32; 32], ends: [u32; 32], count: u32, marked: [bool; 32]) {
    let mut cursor = 0u32;
    let mut active = false;
    let mut end = 0u32;
    let mut first = true;
    let mut dot = false;
    let mut previous_dot = false;
    for i in 0..512 {
        if cursor < count {
            if i == starts[cursor] {
                active = marked[cursor]; end = ends[cursor];
                first = true; dot = false; previous_dot = false;
            }
            if active & (i < end) {
                let c = value[i];
                if first {
                    assert((c >= 97) & (c <= 122), "Invalid ARM provider namespace");
                    first = false;
                }
                assert(((c >= 97) & (c <= 122)) | ((c >= 48) & (c <= 57)) | (c == 46), "Invalid ARM provider namespace");
                assert(!((c == 46) & previous_dot), "Invalid ARM provider namespace");
                dot = dot | (c == 46); previous_dot = c == 46;
            }
            if (end > 0) & (i + 1 == end) {
                if active { assert(dot & !previous_dot, "Invalid ARM provider namespace"); }
                active = false; end = 0; cursor += 1;
            }
        }
    }
    assert(cursor == count, "Incomplete ARM namespace scan");
}

fn role_scope(value: [u8; 512], starts: [u32; 32], ends: [u32; 32], count: u32) {
    assert(count >= 6, "Invalid role assignment scope");
    let scope_count = count - 4;
    assert(segment(value, starts[scope_count], ends[scope_count], "providers".as_bytes()) &
        segment(value, starts[scope_count + 1], ends[scope_count + 1], "microsoft.authorization".as_bytes()) &
        segment(value, starts[scope_count + 2], ends[scope_count + 2], "roleassignments".as_bytes()), "Invalid role assignment suffix");
    assert(ends[count - 1] - starts[count - 1] == 36, "Invalid role assignment name");
    let mut quoted = [0u8; 38]; quoted[0] = 34; quoted[37] = 34;
    for i in 0..36 { quoted[i + 1] = value[starts[count - 1] + i]; }
    let _ = uuid(quoted);
    let group = (scope_count >= 4) & segment(value, starts[2], ends[2], "resourcegroups".as_bytes());
    let base = if group { 4u32 } else { 2u32 };
    if scope_count != base {
        // 0 first providers marker; 1 namespace; 2 required first type;
        // 3 name; 4 complete pair, followed by child type or extension marker.
        let mut state = 0u8;
        let mut marked = [false; 32];
        for i in 0..32 {
            if (i >= base) & (i < scope_count) {
                let marker = segment(value, starts[i], ends[i], "providers".as_bytes());
                if state == 0 { assert(marker, "Invalid role assignment scope"); state = 1; }
                else if state == 1 { marked[i] = true; state = 2; }
                else if state == 2 { assert(!marker, "Missing ARM resource type"); state = 3; }
                else if state == 3 { state = 4; }
                else { state = if marker { 1 } else { 3 }; }
            }
        }
        assert(state == 4, "Incomplete role assignment resource scope");
        namespaces(value, starts, ends, count, marked);
    }
}

// Codes 1..14 each bind one exact catalog action to a fixed ARM resource shape.
fn classify(selected: Row) -> u8 {
    let value = selected.resource;
    let (starts, ends, count) = tokenize::<32, 1>(value, selected.lengths[4]);
    assert(segment(value, starts[0], ends[0], "subscriptions".as_bytes()) &
        segment(value, starts[1], ends[1], selected.ids[2]), "Wrong catalog ARM scope");
    for i in 0..32 {
        if i < count {
            assert(!segment(value, starts[i], ends[i], ".".as_bytes()) &
                !segment(value, starts[i], ends[i], "..".as_bytes()), "Unsupported ARM name segment");
        }
    }
    let rg = (count >= 4) & segment(value, starts[2], ends[2], "resourcegroups".as_bytes());
    let providers = segment(value, starts[4], ends[4], "providers".as_bytes());
    let mut kind: u8 = 0;
    if (count == 8) & rg & providers & (equal(selected.operation, selected.lengths[1], "microsoft.network/networksecuritygroups/write".as_bytes()) | equal(selected.operation, selected.lengths[1], "microsoft.network/networksecuritygroups/delete".as_bytes())) &
        segment(value, starts[5], ends[5], "microsoft.network".as_bytes()) &
        segment(value, starts[6], ends[6], "networksecuritygroups".as_bytes()) { kind = 1; }
    if (count == 8) & rg & providers & (equal(selected.operation, selected.lengths[1], "microsoft.compute/virtualmachines/write".as_bytes())) &
        segment(value, starts[5], ends[5], "microsoft.compute".as_bytes()) &
        segment(value, starts[6], ends[6], "virtualmachines".as_bytes()) { kind = 2; }
    if (count == 8) & rg & providers & (equal(selected.operation, selected.lengths[1], "microsoft.web/sites/write".as_bytes())) &
        segment(value, starts[5], ends[5], "microsoft.web".as_bytes()) &
        segment(value, starts[6], ends[6], "sites".as_bytes()) { kind = 3; }
    if (count == 8) & rg & providers & (equal(selected.operation, selected.lengths[1], "microsoft.containerservice/managedclusters/write".as_bytes())) &
        segment(value, starts[5], ends[5], "microsoft.containerservice".as_bytes()) &
        segment(value, starts[6], ends[6], "managedclusters".as_bytes()) { kind = 4; }
    if (count == 8) & rg & providers & (equal(selected.operation, selected.lengths[1], "microsoft.network/virtualnetworks/write".as_bytes())) &
        segment(value, starts[5], ends[5], "microsoft.network".as_bytes()) &
        segment(value, starts[6], ends[6], "virtualnetworks".as_bytes()) { kind = 5; }
    if (count == 8) & rg & providers & (equal(selected.operation, selected.lengths[1], "microsoft.storage/storageaccounts/write".as_bytes())) &
        segment(value, starts[5], ends[5], "microsoft.storage".as_bytes()) &
        segment(value, starts[6], ends[6], "storageaccounts".as_bytes()) { kind = 6; }
    if (count == 8) & rg & providers & (equal(selected.operation, selected.lengths[1], "microsoft.keyvault/vaults/write".as_bytes())) &
        segment(value, starts[5], ends[5], "microsoft.keyvault".as_bytes()) &
        segment(value, starts[6], ends[6], "vaults".as_bytes()) { kind = 7; }
    if (count == 8) & rg & providers & (equal(selected.operation, selected.lengths[1], "microsoft.insights/metricalerts/write".as_bytes())) &
        segment(value, starts[5], ends[5], "microsoft.insights".as_bytes()) &
        segment(value, starts[6], ends[6], "metricalerts".as_bytes()) { kind = 8; }
    if (count == 10) & rg & providers &
        equal(selected.operation, selected.lengths[1], "microsoft.sql/servers/databases/write".as_bytes()) &
        segment(value, starts[5], ends[5], "microsoft.sql".as_bytes()) &
        segment(value, starts[6], ends[6], "servers".as_bytes()) &
        segment(value, starts[8], ends[8], "databases".as_bytes()) { kind = 9; }
    if (count == 10) & rg & providers &
        equal(selected.operation, selected.lengths[1], "microsoft.datafactory/factories/pipelines/write".as_bytes()) &
        segment(value, starts[5], ends[5], "microsoft.datafactory".as_bytes()) &
        segment(value, starts[6], ends[6], "factories".as_bytes()) &
        segment(value, starts[8], ends[8], "pipelines".as_bytes()) { kind = 10; }
    if (count == 4) & rg &
        (equal(selected.operation, selected.lengths[1], "microsoft.resources/subscriptions/resourcegroups/write".as_bytes()) |
         equal(selected.operation, selected.lengths[1], "microsoft.resources/subscriptions/resourcegroups/delete".as_bytes())) { kind = 11; }
    let deployment_base = if rg { 4u32 } else { 2u32 };
    if (count == deployment_base + 4) &
        equal(selected.operation, selected.lengths[1], "microsoft.resources/deployments/write".as_bytes()) &
        segment(value, starts[deployment_base], ends[deployment_base], "providers".as_bytes()) &
        segment(value, starts[deployment_base + 1], ends[deployment_base + 1], "microsoft.resources".as_bytes()) &
        segment(value, starts[deployment_base + 2], ends[deployment_base + 2], "deployments".as_bytes()) { kind = 12; }
    if equal(selected.operation, selected.lengths[1], "microsoft.authorization/roleassignments/write".as_bytes()) {
        role_scope(value, starts, ends, count); kind = 13;
    }
    if (count >= 8) & rg & providers &
        equal(selected.operation, selected.lengths[1], "microsoft.web/sites/slots/slotsswap/action".as_bytes()) &
        segment(value, starts[5], ends[5], "microsoft.web".as_bytes()) &
        segment(value, starts[6], ends[6], "sites".as_bytes()) {
        // The claim identifies the authenticated action, never source/destination slots or runtime state.
        let scope_count = if count % 2 == 1 {
            assert(segment(value, starts[count - 1], ends[count - 1], "slotsswap".as_bytes()), "Invalid swap action suffix");
            count - 1
        } else { count };
        for i in 0..32 {
            if (i >= 8) & (i < scope_count) & (i % 2 == 0) {
                assert(!segment(value, starts[i], ends[i], "providers".as_bytes()), "Swap scope leaves site provider");
            }
        }
        kind = 14;
    }
    assert(kind != 0, "Unsupported catalog operation/resource pair");
    kind
}

fn check<let CATALOG: u32>(mut selected: Row, mut other: Row, cutoff_ms: u64, profile_code: u8) {
    if CATALOG == 1 {
        // Authenticate original bytes in open(), then normalize each operation
        // once for catalog classification and same-operation conflict checks.
        for i in 0..94 {
            selected.operation[i] = lower(selected.operation[i]);
            other.operation[i] = lower(other.operation[i]);
        }
    }
    assert(cutoff_ms <= 8640000000000000, "Invalid Azure cutoff");
    assert(equal(selected.event, selected.lengths[0], "EndRequest".as_bytes()), "Activity is not terminal");
    assert(equal(selected.status, selected.lengths[2], "Succeeded".as_bytes()), "Activity did not succeed");
    if CATALOG == 1 {
        assert(classify(selected) == profile_code, "Authenticated catalog profile mismatch");
    } else {
        assert(equal(selected.operation, selected.lengths[1], "Microsoft.Network/networkSecurityGroups/securityRules/write".as_bytes()) |
            equal(selected.operation, selected.lengths[1], "Microsoft.Network/networkSecurityGroups/securityRules/delete".as_bytes()), "Unsupported Activity operation");
        resource(selected.resource, selected.lengths[4], selected.ids[2]);
    }
    let _ = source::json::timestamp_day(selected.timestamp, selected.lengths[3], cutoff_ms, 14);
    assert(other.ids[5] == selected.ids[5], "Mixed Activity correlation");
    let same_operation = other.ids[4] == selected.ids[4];
    let same_event = other.ids[3] == selected.ids[3];
    assert(!same_event | same_operation, "Conflicting Activity event ID");
    if same_operation {
        assert(other.ids[0] == selected.ids[0], "Conflicting Activity actor");
        assert(other.ids[1] == selected.ids[1], "Conflicting Activity tenant");
        assert(other.ids[2] == selected.ids[2], "Conflicting Activity subscription");
        assert((other.resource == selected.resource) & (other.lengths[4] == selected.lengths[4]), "Conflicting Activity resource");
        assert((other.operation == selected.operation) & (other.lengths[1] == selected.lengths[1]), "Conflicting Activity operation");
        let terminal = equal(other.event, other.lengths[0], "EndRequest".as_bytes());
        assert(!same_event | terminal, "Conflicting Activity event ID");
        if terminal {
            assert(same_event & equal(other.status, other.lengths[2], "Succeeded".as_bytes()), "Ambiguous Activity terminal outcome");
            assert((other.timestamp == selected.timestamp) & (other.lengths[3] == selected.lengths[3]), "Conflicting Activity event time");
        }
    }
}

fn open(hashes: [[u8; 32]; 11], lengths: [u32; 5], ids: [[u8; 54]; 6], event: [u8; 48],
    operation: [u8; 112], status: [u8; 48], timestamp: [u8; 48], resource: [u8; 530]) -> Row {
    let mut identifiers = [[0u8; 36]; 6];
    for i in 0..6 { identifiers[i] = uuid(source::commitment::authenticate::<38>(ids[i], 38, hashes[i])); }
    let (event, event_len) = string::<30>(source::commitment::authenticate::<32>(event, lengths[0], hashes[6]), lengths[0]);
    let (operation, operation_len) = string::<94>(source::commitment::authenticate::<96>(operation, lengths[1], hashes[7]), lengths[1]);
    let (status, status_len) = string::<30>(source::commitment::authenticate::<32>(status, lengths[2], hashes[8]), lengths[2]);
    let (timestamp, time_len) = string::<30>(source::commitment::authenticate::<32>(timestamp, lengths[3], hashes[9]), lengths[3]);
    let (mut resource, resource_len) = string::<512>(source::commitment::authenticate::<514>(resource, lengths[4], hashes[10]), lengths[4]);
    for i in 0..512 { resource[i] = lower(resource[i]); }
    Row { ids: identifiers, event, operation, status, timestamp, resource,
        lengths: [event_len, operation_len, status_len, time_len, resource_len] }
}

// The inspector binds row zero to the selected event and requires this proof for every complete-correlation row.
pub fn verify_rule(hashes: [[[u8; 32]; 11]; 2], lengths: [[u32; 5]; 2], cutoff_ms: u64,
    ids: [[[u8; 54]; 6]; 2], event: [[u8; 48]; 2], operation: [[u8; 112]; 2], status: [[u8; 48]; 2],
    timestamp: [[u8; 48]; 2], resource: [[u8; 530]; 2]) {
    let selected = open(hashes[0], lengths[0], ids[0], event[0], operation[0], status[0], timestamp[0], resource[0]);
    let other = open(hashes[1], lengths[1], ids[1], event[1], operation[1], status[1], timestamp[1], resource[1]);
    check::<0>(selected, other, cutoff_ms, 0);
}

pub fn verify_catalog(hashes: [[[u8; 32]; 11]; 2], lengths: [[u32; 5]; 2], cutoff_ms: u64, profile_code: u8,
    ids: [[[u8; 54]; 6]; 2], event: [[u8; 48]; 2], operation: [[u8; 112]; 2], status: [[u8; 48]; 2],
    timestamp: [[u8; 48]; 2], resource: [[u8; 530]; 2]) {
    let selected = open(hashes[0], lengths[0], ids[0], event[0], operation[0], status[0], timestamp[0], resource[0]);
    let other = open(hashes[1], lengths[1], ids[1], event[1], operation[1], status[1], timestamp[1], resource[1]);
    check::<1>(selected, other, cutoff_ms, profile_code);
}

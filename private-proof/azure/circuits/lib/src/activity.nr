use source::json;
// Experimental: passes type checking but exceeds the current compiler memory guard; not an accepted proof circuit.
mod tests;

global NONE: u32 = 0xffffffff;
global ARRAY: u8 = 1;
global OBJECT: u8 = 2;
global KEY: u8 = 6;
struct Document<let T: u32> {
    parsed: json::Json<T>,
    tags: [u8; T],
}

// Two 31-byte limbs preserve exact keys without field wraparound or a probabilistic hash.
pub fn key_parts<let K: u32>(key: [u8; K]) -> [Field; 2] {
    assert(K <= 62);
    let mut parts = [0 as Field; 2];
    for i in 0..K {
        if i < 31 { parts[0] = parts[0] * 256 + key[i] as Field; }
        else { parts[1] = parts[1] * 256 + key[i] as Field; }
    }
    parts
}

fn classify_keys<let N: u32, let T: u32>(body: [u8; N], len: u32, parsed: json::Json<T>) -> [u8; T] {
    let known = [
        key_parts("value".as_bytes()), key_parts("claims".as_bytes()),
        key_parts("eventDataId".as_bytes()), key_parts("eventName".as_bytes()),
        key_parts("eventTimestamp".as_bytes()), key_parts("operationId".as_bytes()),
        key_parts("operationName".as_bytes()), key_parts("status".as_bytes()),
        key_parts("correlationId".as_bytes()), key_parts("resourceId".as_bytes()),
        key_parts("subscriptionId".as_bytes()),
        key_parts("http://schemas.microsoft.com/identity/claims/objectidentifier".as_bytes()),
        key_parts("http://schemas.microsoft.com/identity/claims/tenantid".as_bytes()),
    ];
    let lengths: [u32; 13] = [5, 6, 11, 9, 14, 11, 13, 6, 13, 10, 14, 61, 53];
    let mut tags = [0u8; T];
    let mut cursor = 0;
    let mut active = 0;
    let mut start = 0;
    let mut end = 0;
    let mut parts = [0 as Field; 2];
    for i in 0..N {
        if i < len {
            if cursor < parsed.count {
                if parsed.nodes[cursor].start == i {
                    if parsed.nodes[cursor].kind == KEY {
                        active = cursor;
                        start = i;
                        end = parsed.nodes[cursor].end;
                        parts = [0 as Field; 2];
                    }
                    cursor += 1;
                }
            }
            if (i > start) & (i + 1 < end) {
                let at = i - start - 1;
                if at < 31 { parts[0] = parts[0] * 256 + body[i] as Field; }
                else if at < 62 { parts[1] = parts[1] * 256 + body[i] as Field; }
            }
            if (end > 0) & (i + 1 == end) {
                let mut tag = 0;
                for k in 0..13 {
                    if (parts == known[k]) & (end - start - 2 == lengths[k]) { tag = (k + 1) as u8; }
                }
                tags[active] = tag;
                end = 0;
            }
        }
    }
    assert(cursor == parsed.count, "Unclassified JSON nodes");
    // Attach each exact key tag to its value once, instead of a private lookup per member scan.
    let mut fields = [0u8; T];
    for i in 0..T {
        let node = parsed.nodes[i];
        if (i < parsed.count) & (node.kind != KEY) & (node.key != NONE) {
            fields[i] = tags[node.key];
        }
    }
    fields
}


pub struct Action {
    pub correlation: [u8; 36],
    pub operation_id: [u8; 36],
    pub event_id: [u8; 36],
    pub resource: [u8; 512],
    pub resource_len: u32,
    pub timestamp: [u8; 30],
    pub timestamp_len: u32,
    pub deleted: bool,
}

// The caller's complete lexical pass requires literal ASCII keys, excluding escaped aliases.
fn member<let T: u32>(tree: Document<T>, parent: u32, key: u8) -> u32 {
    assert(tree.parsed.nodes[parent].kind == OBJECT, "Expected Azure object");
    let mut found = NONE;
    for i in 0..T {
        if (i < tree.parsed.count) & (tree.parsed.nodes[i].parent == parent) & (tree.parsed.nodes[i].kind != KEY) {
            if tree.tags[i] == key {
                assert(found == NONE, "Duplicate Azure field");
                found = i;
            }
        }
    }
    assert(found != NONE, "Missing Azure field");
    found
}

fn lower(c: u8) -> u8 { if (c >= 65) & (c <= 90) { c + 32 } else { c } }
fn uuid<let N: u32>(body: [u8; N], node: json::Node) -> [u8; 36] {
    let (mut value, len): ([u8; 36], u32) = json::ascii_string(body, node);
    assert(len == 36, "Invalid Azure UUID");
    for i in 0..36 {
        let c = lower(value[i]);
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) { assert(c == 45, "Invalid Azure UUID"); }
        else { assert(((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)), "Invalid Azure UUID"); }
        value[i] = c;
    }
    value
}
fn id<let N: u32, let T: u32>(body: [u8; N], tree: Document<T>, parent: u32, key: u8) -> [u8; 36] {
    uuid(body, tree.parsed.nodes[member(tree, parent, key)])
}
fn literal<let N: u32, let T: u32, let V: u32>(body: [u8; N], tree: Document<T>, parent: u32, key: u8, value: [u8; V]) -> bool {
    json::string_eq(body, tree.parsed.nodes[member(tree, parent, key)], value)
}
fn resource<let N: u32, let T: u32>(body: [u8; N], tree: Document<T>, row: u32, subscription: [u8; 36]) -> ([u8; 512], u32) {
    let (mut value, len): ([u8; 512], u32) = json::ascii_string(body, tree.parsed.nodes[member(tree, row, 10)]);
    let mut starts = [0u32; 10];
    let mut ends = [0u32; 10];
    let mut count = 0;
    assert((len > 1) & (value[0] == 47), "Expected ARM resource path");
    for i in 0..512 {
        if i < len {
            let c = lower(value[i]); value[i] = c;
            if c == 47 {
                if count > 0 { ends[count - 1] = i; }
                assert(count < 10, "Wrong ARM rule path"); starts[count] = i + 1; count += 1;
            } else {
                assert(((c >= 97) & (c <= 122)) | ((c >= 48) & (c <= 57)) | (c == 45) | (c == 46) | (c == 95) | (c == 40) | (c == 41), "Unsupported ARM name");
            }
        }
    }
    assert(count == 10, "Wrong ARM rule path"); ends[9] = len;
    for i in 0..10 { assert(starts[i] < ends[i], "Empty ARM path segment"); }
    assert(segment(value, starts[0], ends[0], "subscriptions".as_bytes()) &
        segment(value, starts[1], ends[1], subscription) &
        segment(value, starts[2], ends[2], "resourcegroups".as_bytes()) &
        segment(value, starts[4], ends[4], "providers".as_bytes()) &
        segment(value, starts[5], ends[5], "microsoft.network".as_bytes()) &
        segment(value, starts[6], ends[6], "networksecuritygroups".as_bytes()) &
        segment(value, starts[8], ends[8], "securityrules".as_bytes()), "Wrong ARM rule path");
    (value, len)
}
fn segment<let M: u32>(value: [u8; 512], start: u32, end: u32, expected: [u8; M]) -> bool {
    let mut equal = end - start == M;
    for i in 0..M { if start + i < 512 { equal = equal & (value[start + i] == expected[i]); } else { equal = false; } }
    equal
}
fn nested_value<let N: u32, let T: u32, let V: u32>(body: [u8; N], tree: Document<T>, row: u32, key: u8, value: [u8; V]) -> bool {
    literal(body, tree, member(tree, row, key), 1, value)
}
fn actor<let N: u32, let T: u32>(body: [u8; N], tree: Document<T>, row: u32, object_id: [u8; 36], tenant: [u8; 36]) {
    let claims = member(tree, row, 2);
    assert(id(body, tree, claims, 12) == object_id, "Wrong Activity actor");
    assert(id(body, tree, claims, 13) == tenant, "Wrong Activity tenant");
}

// Call only on the complete authenticated correlation response; selected-time slices cannot exclude conflicts.
// The caller binds actor/tenant/subscription and the returned private joins to the other source proofs.
pub fn action<let N: u32, let T: u32, let R: u32>(body: [u8; N], len: u32, selected: u32,
    object_id: [u8; 36], tenant: [u8; 36], subscription: [u8; 36], cutoff_ms: u64) -> Action {
    assert(cutoff_ms <= 8640000000000000, "Invalid Azure cutoff");
    let parsed: json::Json<T> = json::parse_ascii_keys(body, len);
    let tree = Document { parsed, tags: classify_keys(body, len, parsed) };
    assert(tree.parsed.nodes[0].children == 1, "Incomplete or unexpected Activity response");
    let values = member(tree, 0, 1);
    let count = tree.parsed.nodes[values].children;
    assert((tree.parsed.nodes[values].kind == ARRAY) & (count > 0) & (count <= R) & (R <= 8) & (selected < count), "Activity response bound");
    let chosen = json::child(tree.parsed, values, selected);
    actor(body, tree, chosen, object_id, tenant);
    assert(id(body, tree, chosen, 11) == subscription, "Wrong Activity subscription");
    assert(nested_value(body, tree, chosen, 4, "EndRequest".as_bytes()), "Activity is not terminal");
    assert(nested_value(body, tree, chosen, 8, "Succeeded".as_bytes()), "Activity did not succeed");
    let deleted = nested_value(body, tree, chosen, 7, "Microsoft.Network/networkSecurityGroups/securityRules/delete".as_bytes());
    assert(deleted | nested_value(body, tree, chosen, 7, "Microsoft.Network/networkSecurityGroups/securityRules/write".as_bytes()), "Unsupported Activity operation");
    let operation_id = id(body, tree, chosen, 6);
    let event_id = id(body, tree, chosen, 3);
    let correlation = id(body, tree, chosen, 9);
    let (chosen_resource, resource_len) = resource(body, tree, chosen, subscription);
    let (timestamp, timestamp_len): ([u8; 30], u32) = json::ascii_string(body, tree.parsed.nodes[member(tree, chosen, 5)]);
    let _ = json::timestamp_day(timestamp, timestamp_len, cutoff_ms, 14);
    for position in 0..R {
        if position < count {
            let row = json::child(tree.parsed, values, position);
            assert(id(body, tree, row, 9) == correlation, "Mixed Activity correlation");
            let same_operation = id(body, tree, row, 6) == operation_id;
            let same_event = id(body, tree, row, 3) == event_id;
            assert(!same_event | same_operation, "Conflicting Activity event ID");
            if same_operation {
                actor(body, tree, row, object_id, tenant);
                assert(id(body, tree, row, 11) == subscription, "Conflicting Activity subscription");
                let (other_resource, other_len) = resource(body, tree, row, subscription);
                assert((other_resource == chosen_resource) & (other_len == resource_len), "Conflicting Activity resource");
                assert((deleted & nested_value(body, tree, row, 7, "Microsoft.Network/networkSecurityGroups/securityRules/delete".as_bytes())) |
                    (!deleted & nested_value(body, tree, row, 7, "Microsoft.Network/networkSecurityGroups/securityRules/write".as_bytes())), "Conflicting Activity operation");
                let terminal = nested_value(body, tree, row, 4, "EndRequest".as_bytes());
                assert(!same_event | terminal, "Conflicting Activity event ID");
                if terminal {
                    assert(same_event & nested_value(body, tree, row, 8, "Succeeded".as_bytes()), "Ambiguous Activity terminal outcome");
                    let (other_time, other_time_len): ([u8; 30], u32) = json::ascii_string(body, tree.parsed.nodes[member(tree, row, 5)]);
                    assert((timestamp == other_time) & (timestamp_len == other_time_len), "Conflicting Activity event time");
                }
            }
        }
    }
    Action { correlation, operation_id, event_id, resource: chosen_resource, resource_len, timestamp, timestamp_len, deleted }
}

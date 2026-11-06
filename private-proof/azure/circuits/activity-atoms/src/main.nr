// The inspector binds row zero to the selected event and requires this proof for every complete-correlation row.
fn main(hashes: pub [[[u8; 32]; 11]; 2], lengths: pub [[u32; 5]; 2], cutoff_ms: pub u64,
    ids: [[[u8; 54]; 6]; 2], event: [[u8; 48]; 2], operation: [[u8; 112]; 2], status: [[u8; 48]; 2],
    timestamp: [[u8; 48]; 2], resource: [[u8; 530]; 2]) {
    predicates::verify_rule(hashes, lengths, cutoff_ms, ids, event, operation, status, timestamp, resource);
}

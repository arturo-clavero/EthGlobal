mod facts;
use gcp_private_json::commitment;

// Slots: request EventId, outer EventId, decoded eventID, outer EventTime,
// decoded eventTime and decoded roleName. The verifier derives this order from
// authenticated structure and supplies its own attempt cutoff.
fn main(
    hashes: pub [[u8; 32]; 6], lengths: pub [u32; 6], cutoff_ms: pub u64,
    request_id_preimage: [u8; 54], outer_id_preimage: [u8; 54], event_id_preimage: [u8; 54], outer_time_preimage: [u8; 528],
    event_time_preimage: [u8; 48], role_preimage: [u8; 82], epoch_ms: u64,
) {
    for i in 0..3 { assert(lengths[i] == 38, "Invalid event ID length"); }
    let request = commitment::authenticate(request_id_preimage, lengths[0], hashes[0]);
    let outer = commitment::authenticate(outer_id_preimage, lengths[1], hashes[1]);
    let event = commitment::authenticate(event_id_preimage, lengths[2], hashes[2]);
    facts::event_id(request);
    assert((request == outer) & (request == event), "Event ID mismatch");
    let number = commitment::authenticate(outer_time_preimage, lengths[3], hashes[3]);
    let timestamp = commitment::authenticate(event_time_preimage, lengths[4], hashes[4]);
    facts::timestamps(timestamp, lengths[4], number, lengths[3], epoch_ms, cutoff_ms);
    let role = commitment::authenticate(role_preimage, lengths[5], hashes[5]);
    facts::role_name(role, lengths[5]);
}

mod tests;

// The inspector must bind this commitment to the selected ARM subscription's state field.
fn main(hash: pub [u8; 32], preimage: [u8; 25]) {
    let state = source::commitment::authenticate::<9>(preimage, 9, hash);
    assert(state == "\"Enabled\"".as_bytes(), "Subscription must be enabled");
}

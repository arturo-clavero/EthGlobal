fn main(commitment: pub [u8; 32], length: pub u32, preimage: [u8; 528]) -> pub u8 {
    let bytes = gcp_private_json::commitment::authenticate::<512>(preimage, length, commitment);
    gcp_private_json::atomic::json_atom(bytes, length)
}

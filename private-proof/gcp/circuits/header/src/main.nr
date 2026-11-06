fn main(commitment: pub [u8; 32], length: pub u32, preimage: [u8; 2064]) {
    let bytes = gcp_private_json::commitment::authenticate::<2048>(preimage, length, commitment);
    gcp_private_json::atomic::header_value(bytes, length);
}

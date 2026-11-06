use aws_private_json::escaped;

// The verifier must bind the encoded commitment/range to TLS and the decoded
// commitment/length/kind to the independently reconstructed inner JSON position.
fn main(
    encoded_commitment: pub [u8; 32],
    encoded_length: pub u32,
    decoded_commitment: pub [u8; 32],
    decoded_length: pub u32,
    encoded_preimage: [u8; 528],
    decoded_preimage: [u8; 528],
) -> pub u8 {
    let encoded = gcp_private_json::commitment::authenticate::<512>(
        encoded_preimage, encoded_length, encoded_commitment,
    );
    let decoded = gcp_private_json::commitment::authenticate::<512>(
        decoded_preimage, decoded_length, decoded_commitment,
    );
    escaped::atom(encoded, encoded_length, decoded, decoded_length)
}

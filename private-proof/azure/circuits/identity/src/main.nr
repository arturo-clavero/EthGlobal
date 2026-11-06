use source::{commitment, http};

fn graph_identity<let N: u32>(response: [u8; N], length: u32) -> [u8; 36] {
    let message = http::parse(response, length);
    assert(http::equals(response, http::Span { start: 0, end: message.line_end },
        "HTTP/1.1 200 OK".as_bytes(), false), "Graph status mismatch");
    let (found, content_type) = http::header(response, message, "content-type".as_bytes());
    assert(found & (content_type.end >= content_type.start + 16), "Graph JSON content type required");
    assert(http::equals(response, http::Span { start: content_type.start, end: content_type.start + 16 },
        "application/json".as_bytes(), true), "Graph JSON content type required");
    if content_type.end != content_type.start + 16 {
        assert(response[content_type.start + 16] == 59, "Graph JSON content type required");
    }
    // Pin the complete selected Graph response; parsing hints cannot substitute a nested ID.
    let template = "{\"@odata.context\":\"https://graph.microsoft.com/v1.0/$metadata#users(id)/$entity\",\"id\":\"00000000-0000-0000-0000-000000000000\"}".as_bytes();
    assert(message.body_len == template.len(), "Graph response shape mismatch");
    let offset = template.len() - 38;
    let mut actor = [0u8; 36];
    for i in 0..template.len() {
        if (i < offset) | (i >= offset + 36) {
            assert(message.body[i] == template[i], "Graph response shape mismatch");
        }
    }
    for i in 0..36 {
        let c = message.body[offset + i];
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) {
            assert(c == 45, "Invalid Graph object ID");
        } else {
            assert(((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)), "Invalid Graph object ID");
        }
        actor[i] = c;
    }
    actor
}

// Bind hash/length to a fresh Graph TLS receipt and challenge to the server's attempt.
// This proves private Graph identity, not the later Azure action/tenant predicate.
fn main(
    response_hash: pub [u8; 32],
    response_length: pub u32,
    challenge: pub [u8; 32],
    identity_binding: pub [u8; 32],
    response_preimage: [u8; 1040],
    salt: [u8; 32],
) {
    let response = commitment::authenticate::<1024>(response_preimage, response_length, response_hash);
    let actor = graph_identity(response, response_length);
    let domain = "azure-identity-v1".as_bytes();
    let mut input = [0u8; 117];
    for i in 0..domain.len() { input[i] = domain[i]; }
    for i in 0..32 { input[domain.len() + i] = challenge[i]; input[domain.len() + 32 + i] = salt[i]; }
    for i in 0..36 { input[domain.len() + 64 + i] = actor[i]; }
    assert(sha256::sha256_var(input, input.len()) == identity_binding, "Identity challenge binding mismatch");
}

#[test]
fn accepts_complete_identity_without_revealing_actor() {
    let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 125\r\n\r\n{\"@odata.context\":\"https://graph.microsoft.com/v1.0/$metadata#users(id)/$entity\",\"id\":\"11111111-2222-3333-4444-555555555555\"}".as_bytes();
    assert(graph_identity(response, response.len()) == "11111111-2222-3333-4444-555555555555".as_bytes());
}

#[test(should_fail)]
fn rejects_nested_identity_substitution() {
    let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 63\r\n\r\n{\"attacker\":{\"id\":\"11111111-2222-3333-4444-555555555555\"},\"id\":0}".as_bytes();
    let _ = graph_identity(response, response.len());
}

#[test(should_fail_with = "Graph status mismatch")]
fn rejects_provider_error() {
    let response = "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}".as_bytes();
    let _ = graph_identity(response, response.len());
}

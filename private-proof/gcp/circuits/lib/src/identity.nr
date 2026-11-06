use crate::{commitment, http, json, scope};

fn required_header<let N: u32, let M: u32, let V: u32>(
    data: [u8; N], message: http::Message<N>, name: [u8; M], value: [u8; V], fold: bool,
) {
    let (found, span) = http::header(data, message, name);
    assert(found, "Missing identity HTTP header");
    assert(http::equals(data, span, value, fold), "Wrong identity HTTP header");
}

fn json_content_type<let N: u32>(data: [u8; N], message: http::Message<N>) {
    let (found, value) = http::header(data, message, "content-type".as_bytes());
    assert(found, "Missing identity response content type");
    let length = value.end - value.start;
    assert(length >= 16, "Wrong identity response content type");
    assert(http::equals(data, http::Span { start: value.start, end: value.start + 16 }, "application/json".as_bytes(), true), "Wrong identity response content type");
    if length != 16 {
        assert(length >= 30, "Wrong identity response charset");
        assert(data[value.start + 16] == 59, "Wrong identity response charset");
        let charset_start = value.end - 13;
        assert(http::equals(data, http::Span { start: charset_start, end: value.end }, "charset=utf-8".as_bytes(), true), "Wrong identity response charset");
        for i in 0..N {
            if (i >= value.start + 17) & (i < charset_start) {
                assert((data[i] == 32) | (data[i] == 9), "Wrong identity response charset");
            }
        }
    }
}

// S/R are transcript capacities excluding the16-byte opening blinder; B bounds
// the decoded identity JSON. The caller binds hashes/lengths to the verified
// accounts.google.com TLS session and nonce to its authorized challenge.
// Only the salted scope hash is returned; email, id, project and salt stay private.
pub fn verify<let S: u32, let R: u32, let B: u32>(
    sent_preimage: [u8; S + 16], sent_len: u32, sent_hash: [u8; 32],
    recv_preimage: [u8; R + 16], recv_len: u32, recv_hash: [u8; 32],
    nonce: [u8; 43], account: u8, project: [u8; 30], project_len: u32,
    salt: [u8; 32], expected_scope: [u8; 32],
) -> [u8; 32] {
    let sent = commitment::authenticate::<S>(sent_preimage, sent_len, sent_hash);
    let recv = commitment::authenticate::<R>(recv_preimage, recv_len, recv_hash);
    let request = http::parse_request(sent, sent_len);
    assert(account < 10, "Invalid Google account selector");
    let mut request_line = "POST /ListAccounts?json=standard&authuser=0 HTTP/1.1".as_bytes();
    request_line[request_line.len() - 10] = 48 + account;
    assert(http::equals(sent, http::Span { start: 0, end: request.line_end }, request_line, false), "Wrong identity request target");
    required_header(sent, request, "host".as_bytes(), "accounts.google.com".as_bytes(), true);
    required_header(sent, request, "x-16signals-nonce".as_bytes(), nonce, false);
    required_header(sent, request, "content-type".as_bytes(), "application/x-www-form-urlencoded".as_bytes(), false);
    assert((request.body_len == 1) & (request.body[0] == 32), "Wrong identity request body");

    let response = http::parse(recv, recv_len);
    assert(http::equals(recv, http::Span { start: 0, end: response.line_end }, "HTTP/1.1 200 OK".as_bytes(), false), "Wrong identity response status");
    json_content_type(recv, response);
    assert(B <= R, "Identity body capacity exceeds transcript capacity");
    assert(response.body_len <= B, "Identity JSON byte limit");
    let mut body = [0u8; B];
    for i in 0..B { body[i] = response.body[i]; }
    let selected = json::identity(body, response.body_len, account as u32);
    let actual_scope = scope::hash(nonce, salt, account, project, project_len, selected);
    assert(actual_scope == expected_scope, "Scope commitment mismatch");
    actual_scope
}

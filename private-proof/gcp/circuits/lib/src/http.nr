// Hints locate framing; constrained checks cover every authenticated byte before extraction.
global HEADERS: u32 = 64;
global CHUNKS: u32 = 64;

pub struct Span { pub start: u32, pub end: u32 }
pub struct Header { pub start: u32, pub colon: u32, pub end: u32, pub value: Span }
struct Chunk { start: u32, end: u32, size: u32, output: u32 }
struct Frame<let N: u32> {
    line_end: u32, body_start: u32, headers: [Header; HEADERS], count: u32,
    header_owner: [u32; N], chunks: [Chunk; CHUNKS], chunk_count: u32,
    body_owner: [u32; N],
}
pub struct Message<let N: u32> {
    pub line_end: u32, pub headers: [Header; HEADERS], pub count: u32,
    pub body: [u8; N], pub body_len: u32,
}

fn ows(c: u8) -> bool { (c == 32) | (c == 9) }
fn lower(c: u8) -> u8 { if (c >= 65) & (c <= 90) { c + 32 } else { c } }
fn name_byte(c: u8) -> bool {
    ((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122)) | ((c >= 48) & (c <= 57)) | (c == 45)
}
fn hex(c: u8) -> u32 {
    assert(((c >= 48) & (c <= 57)) | ((lower(c) >= 97) & (lower(c) <= 102)), "Invalid chunk size");
    if c <= 57 { (c - 48) as u32 } else { (lower(c) - 87) as u32 }
}
pub fn equals<let N: u32, let M: u32>(bytes: [u8; N], span: Span, expected: [u8; M], fold: bool) -> bool {
    assert((span.start <= span.end) & (span.end <= N), "Invalid HTTP span");
    let mut same = span.end - span.start == M;
    for i in 0..M {
        if span.start + i < span.end {
            let actual = bytes[span.start + i];
            same = same & (if fold { lower(actual) == lower(expected[i]) } else { actual == expected[i] });
        }
    }
    same
}

unconstrained fn hints<let N: u32>(data: [u8; N], len: u32) -> Frame<N> {
    assert((len >= 4) & (len <= N));
    let mut frame: Frame<N> = std::mem::zeroed();
    let mut cursor = 0;
    while (cursor < len) & (data[cursor] != 13) { cursor += 1; }
    frame.line_end = cursor;
    cursor += 2;
    while (cursor + 1 < len) & (data[cursor] != 13) {
        assert(frame.count < HEADERS, "HTTP header limit");
        let start = cursor;
        while (cursor < len) & (data[cursor] != 58) { cursor += 1; }
        let colon = cursor;
        cursor += 1;
        while (cursor < len) & (data[cursor] != 13) { cursor += 1; }
        let end = cursor;
        let mut value_start = colon + 1;
        while (value_start < end) & ows(data[value_start]) { value_start += 1; }
        let mut value_end = end;
        while (value_end > value_start) & ows(data[value_end - 1]) { value_end -= 1; }
        frame.headers[frame.count] = Header { start, colon, end, value: Span { start: value_start, end: value_end } };
        for i in start..end + 2 { frame.header_owner[i] = frame.count; }
        frame.count += 1;
        cursor += 2;
    }
    frame.body_start = cursor + 2;
    let mut chunked = false;
    for i in 0..frame.count {
        let h = frame.headers[i];
        if equals(data, Span { start: h.start, end: h.colon }, "transfer-encoding".as_bytes(), true) {
            chunked = true;
        }
    }
    if chunked {
        cursor = frame.body_start;
        let mut output = 0;
        let mut done = false;
        while !done {
            assert(frame.chunk_count < CHUNKS, "HTTP chunk limit");
            let start = cursor;
            let mut size = 0;
            while (cursor < len) & (data[cursor] != 13) {
                size = size * 16 + hex(data[cursor]); cursor += 1;
                assert(size <= N, "HTTP chunk limit");
            }
            frame.chunks[frame.chunk_count] = Chunk { start, end: cursor, size, output };
            for i in output..output + size { frame.body_owner[i] = frame.chunk_count; }
            output += size;
            frame.chunk_count += 1;
            cursor += size + 4;
            done = size == 0;
        }
    }
    frame
}

fn crlf<let N: u32>(data: [u8; N], pos: u32, len: u32) {
    assert(pos + 1 < len, "Truncated HTTP framing");
    assert((data[pos] == 13) & (data[pos + 1] == 10), "Invalid HTTP CRLF");
}

fn verify<let N: u32>(data: [u8; N], len: u32, f: Frame<N>) -> Message<N> {
    assert((len >= 4) & (len <= N), "HTTP byte limit");
    assert((f.line_end > 0) & (f.line_end < len), "Invalid HTTP start line");
    crlf(data, f.line_end, len);
    assert(f.count <= HEADERS, "HTTP header limit");
    let mut cursor = f.line_end + 2;
    let mut length_count = 0;
    let mut content_length = 0;
    let mut transfer_count = 0;
    let mut encoding_count = 0;
    for i in 0..HEADERS {
        if i < f.count {
            let h = f.headers[i];
            assert((h.start == cursor) & (h.colon > h.start) & (h.colon < h.end), "Invalid HTTP header positions");
            assert((h.value.start > h.colon) & (h.value.start <= h.value.end) & (h.value.end <= h.end), "Invalid HTTP value positions");
            crlf(data, h.end, len);
            assert(data[h.colon] == 58, "Missing HTTP colon");
            if h.value.start < h.value.end {
                assert(!ows(data[h.value.start]) & !ows(data[h.value.end - 1]), "Untrimmed HTTP value");
            }
            cursor = h.end + 2;
            let key = Span { start: h.start, end: h.colon };
            if equals(data, key, "content-length".as_bytes(), true) {
                length_count += 1;
                let digits = h.value.end - h.value.start;
                assert((digits > 0) & (digits <= 8), "Invalid content length");
                let mut number = 0;
                for j in 0..8 {
                    if j < digits {
                        let c = data[h.value.start + j];
                        assert((c >= 48) & (c <= 57), "Invalid content length");
                        number = number * 10 + (c - 48) as u32;
                        assert(number <= N, "HTTP body limit");
                    }
                }
                content_length = number;
            }
            if equals(data, key, "transfer-encoding".as_bytes(), true) {
                transfer_count += 1;
                assert(equals(data, h.value, "chunked".as_bytes(), true), "Unsupported transfer encoding");
            }
            if equals(data, key, "content-encoding".as_bytes(), true) {
                encoding_count += 1;
                assert(equals(data, h.value, "identity".as_bytes(), true), "Unsupported content encoding");
            }
        }
    }
    crlf(data, cursor, len);
    assert(f.body_start == cursor + 2, "Invalid HTTP body start");
    assert((length_count <= 1) & (transfer_count <= 1) & (encoding_count <= 1), "Duplicate HTTP framing");
    assert((length_count == 0) | (transfer_count == 0), "Ambiguous HTTP framing");
    for i in 0..N {
        if i < f.line_end {
            assert((data[i] >= 32) & (data[i] < 127), "Invalid HTTP start line byte");
        } else if (i >= f.line_end + 2) & (i < cursor) {
            let owner = f.header_owner[i];
            assert(owner < f.count, "Invalid header owner");
            let h = f.headers[owner];
            assert((i >= h.start) & (i < h.end + 2), "Uncovered HTTP header byte");
            if i < h.colon { assert(name_byte(data[i]), "Invalid HTTP header name"); }
            else if (i > h.colon) & (i < h.end) {
                assert(((data[i] >= 32) & (data[i] < 127)) | (data[i] == 9), "Invalid HTTP header value");
                if (i < h.value.start) | (i >= h.value.end) { assert(ows(data[i]), "Hidden HTTP header value"); }
            }
        }
    }
    let mut body: [u8; N] = [0; N];
    let mut body_len = len - f.body_start;
    if transfer_count == 0 {
        assert(f.chunk_count == 0, "Unexpected chunks");
        if length_count == 1 { assert(content_length == body_len, "Wrong HTTP body length"); }
        for i in 0..N { if i < body_len { body[i] = data[f.body_start + i]; } }
    } else {
        assert((f.chunk_count > 0) & (f.chunk_count <= CHUNKS), "HTTP chunk limit");
        let mut wire = f.body_start;
        let mut output = 0;
        for i in 0..CHUNKS {
            if i < f.chunk_count {
                let c = f.chunks[i];
                assert((c.start == wire) & (c.end > c.start) & (c.end - c.start <= 8), "Invalid chunk positions");
                crlf(data, c.end, len);
                let mut size = 0;
                for j in 0..8 { if c.start + j < c.end { size = size * 16 + hex(data[c.start + j]); assert(size <= N, "HTTP chunk limit"); } }
                assert((size == c.size) & (c.output == output), "Wrong chunk size or position");
                crlf(data, c.end + 2 + size, len);
                if i + 1 == f.chunk_count { assert(size == 0, "Missing final chunk"); }
                else { assert(size > 0, "Data after final chunk"); }
                wire = c.end + size + 4;
                output += size;
            }
        }
        assert(wire == len, "Trailing chunk bytes");
        body_len = output;
        assert(body_len <= N, "HTTP body limit");
        for i in 0..N {
            if i < body_len {
                let owner = f.body_owner[i];
                assert(owner < f.chunk_count, "Invalid chunk owner");
                let c = f.chunks[owner];
                assert((i >= c.output) & (i < c.output + c.size), "Uncovered HTTP body byte");
                body[i] = data[c.end + 2 + i - c.output];
            }
        }
    }
    Message { line_end: f.line_end, headers: f.headers, count: f.count, body, body_len }
}

// shortcut: reject chunk extensions/trailers, non-ASCII headers, or >64 headers/chunks; expand only for an observed Google format.
pub fn parse<let N: u32>(data: [u8; N], len: u32) -> Message<N> {
    let frame = unsafe { hints(data, len) };
    verify(data, len, frame)
}

pub fn header<let N: u32, let M: u32>(data: [u8; N], message: Message<N>, name: [u8; M]) -> (bool, Span) {
    let mut found = false;
    let mut value = Span { start: 0, end: 0 };
    for i in 0..HEADERS {
        if i < message.count {
            let h = message.headers[i];
            if equals(data, Span { start: h.start, end: h.colon }, name, true) {
                assert(!found, "Duplicate selected HTTP header");
                found = true;
                value = h.value;
            }
        }
    }
    (found, value)
}

// Requests cannot use the response's EOF-delimited body rule.
pub fn parse_request<let N: u32>(data: [u8; N], len: u32) -> Message<N> {
    let message = parse(data, len);
    let (length, _) = header(data, message, "content-length".as_bytes());
    let (chunked, _) = header(data, message, "transfer-encoding".as_bytes());
    assert((message.body_len == 0) | length | chunked, "Request needs explicit body framing");
    message
}

#[test]
fn content_length_body_and_case_insensitive_header() {
    let data = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}".as_bytes();
    let parsed = parse(data, data.len());
    assert(parsed.body_len == 2);
    assert((parsed.body[0] == 123) & (parsed.body[1] == 125));
    let (found, value) = header(data, parsed, "content-type".as_bytes());
    assert(found & equals(data, value, "application/json".as_bytes(), false));
}

#[test]
fn multiple_chunks_preserve_bytes() {
    let data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n".as_bytes();
    let parsed = parse(data, data.len());
    assert((parsed.body_len == 2) & (parsed.body[0] == 123) & (parsed.body[1] == 125));
}

#[test(should_fail)]
fn dishonest_body_offset_rejected() {
    let data = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".as_bytes();
    let mut frame = unsafe { hints(data, data.len()) };
    frame.body_start += 1;
    let _ = verify(data, data.len(), frame);
}

#[test(should_fail)]
fn dishonest_header_value_cannot_hide_length() {
    let data = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\n{}".as_bytes();
    let mut frame = unsafe { hints(data, data.len()) };
    frame.headers[0].value.start += 1;
    let _ = verify(data, data.len(), frame);
}

#[test(should_fail)]
fn duplicate_length_rejected() {
    let data = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\ncontent-length: 2\r\n\r\n{}".as_bytes();
    let _ = parse(data, data.len());
}

#[test(should_fail)]
fn chunked_length_ambiguity_rejected() {
    let data = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".as_bytes();
    let _ = parse(data, data.len());
}

#[test(should_fail)]
fn trailing_second_response_rejected_by_length() {
    let data = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}HTTP/1.1 200 OK\r\n\r\n{}".as_bytes();
    let _ = parse(data, data.len());
}

#[test(should_fail)]
fn dishonest_chunk_mapping_rejected() {
    let data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\n{\r\n1\r\n}\r\n0\r\n\r\n".as_bytes();
    let mut frame = unsafe { hints(data, data.len()) };
    frame.body_owner[1] = 0;
    let _ = verify(data, data.len(), frame);
}

#[test(should_fail)]
fn dishonest_chunk_size_rejected() {
    let data = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n".as_bytes();
    let mut frame = unsafe { hints(data, data.len()) };
    frame.chunks[0].size = 1;
    let _ = verify(data, data.len(), frame);
}

#[test(should_fail)]
fn folded_header_rejected() {
    let data = "HTTP/1.1 200 OK\r\n bad: value\r\n\r\n{}".as_bytes();
    let _ = parse(data, data.len());
}

#[test(should_fail_with = "Request needs explicit body framing")]
fn unframed_request_body_is_not_authenticated_as_json() {
    let data = "POST /batch HTTP/1.1\r\nHost: logging.clients6.google.com\r\n\r\n{}".as_bytes();
    let _ = parse_request(data, data.len());
}

#[test]
fn empty_request_does_not_need_body_framing() {
    let data = "GET / HTTP/1.1\r\nHost: accounts.google.com\r\n\r\n".as_bytes();
    assert(parse_request(data, data.len()).body_len == 0);
}

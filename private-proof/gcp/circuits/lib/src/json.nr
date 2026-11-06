// Full bounded structure is checked before selecting any private field.
global NONE: u32 = 0xffffffff;
global ARRAY: u8 = 1;
global OBJECT: u8 = 2;
global STRING: u8 = 3;
global NUMBER: u8 = 4;
global LITERAL: u8 = 5;
global KEY: u8 = 6;

struct Node {
    kind: u8,
    start: u32,
    end: u32,
    parent: u32,
    ordinal: u32,
    key: u32,
    children: u32,
}

struct Json<let T: u32> {
    nodes: [Node; T],
    count: u32,
}

pub struct Identity {
    pub email: [u8; 254],
    pub email_len: u32,
    pub id: [u8; 64],
    pub id_len: u32,
}

pub struct Observation {
    pub status: u8,
    pub day: u32,
}

fn whitespace(c: u8) -> bool { (c == 32) | (c == 9) | (c == 10) | (c == 13) }
pub(crate) fn digit(c: u8) -> bool { (c >= 48) & (c <= 57) }
fn alpha(c: u8) -> bool { ((c >= 65) & (c <= 90)) | ((c >= 97) & (c <= 122)) }
fn hex(c: u8) -> bool { digit(c) | ((c >= 65) & (c <= 70)) | ((c >= 97) & (c <= 102)) }
pub(crate) fn number_end(state: u8) -> bool { (state == 2) | (state == 3) | (state == 5) | (state == 8) }

// Shared scalar lexer: JSON tree validation and selective atomic proofs use
// the same escape, UTF-8 and number rules without sharing an AST.
pub(crate) struct StringState {
    escaped: bool,
    unicode_left: u8,
    utf8_left: u8,
    utf8_low: u8,
    utf8_high: u8,
}

pub(crate) fn string_start() -> StringState {
    StringState { escaped: false, unicode_left: 0, utf8_left: 0, utf8_low: 128, utf8_high: 191 }
}

// Input starts after the opening quote. `closed` identifies an unescaped quote.
pub(crate) fn string_byte(state: StringState, c: u8) -> (StringState, bool) {
    let mut next = state;
    let mut closed = false;
    if state.utf8_left > 0 {
        assert((c >= state.utf8_low) & (c <= state.utf8_high), "Invalid JSON UTF-8");
        next.utf8_left -= 1;
        next.utf8_low = 128;
        next.utf8_high = 191;
    } else if state.unicode_left > 0 {
        assert(hex(c), "Invalid JSON Unicode escape");
        next.unicode_left -= 1;
    } else if state.escaped {
        assert((c == 34) | (c == 92) | (c == 47) | (c == 98) | (c == 102) | (c == 110) | (c == 114) | (c == 116) | (c == 117),
            "Invalid JSON escape");
        if c == 117 { next.unicode_left = 4; }
        next.escaped = false;
    } else if c == 34 {
        closed = true;
    } else if c == 92 {
        next.escaped = true;
    } else {
        assert(c >= 32, "Unescaped JSON control byte");
        if c >= 128 {
            assert((c >= 194) & (c <= 244), "Invalid JSON UTF-8 lead");
            next.utf8_left = if c <= 223 { 1 } else if c <= 239 { 2 } else { 3 };
            next.utf8_low = if c == 224 { 160 } else if c == 240 { 144 } else { 128 };
            next.utf8_high = if c == 237 { 159 } else if c == 244 { 143 } else { 191 };
        }
    }
    (next, closed)
}

pub(crate) fn number_start(c: u8) -> u8 {
    assert(digit(c) | (c == 45), "Invalid JSON number");
    if c == 45 { 1 } else if c == 48 { 2 } else { 3 }
}

pub(crate) fn number_byte(state: u8, c: u8) -> u8 {
    let mut next = state;
    if state == 1 {
        assert(digit(c), "Invalid JSON number");
        next = if c == 48 { 2 } else { 3 };
    } else if state == 2 {
        assert((c == 46) | (c == 101) | (c == 69), "Leading zero in JSON number");
        next = if c == 46 { 4 } else { 6 };
    } else if state == 3 {
        assert(digit(c) | (c == 46) | (c == 101) | (c == 69), "Invalid JSON number");
        if c == 46 { next = 4; }
        else if (c == 101) | (c == 69) { next = 6; }
    } else if (state == 4) | (state == 7) {
        assert(digit(c), "Invalid JSON number");
        next = if state == 4 { 5 } else { 8 };
    } else if state == 5 {
        assert(digit(c) | (c == 101) | (c == 69), "Invalid JSON fraction");
        if (c == 101) | (c == 69) { next = 6; }
    } else if state == 6 {
        assert(digit(c) | (c == 45) | (c == 43), "Invalid JSON exponent");
        next = if digit(c) { 8 } else { 7 };
    } else {
        assert((state == 8) & digit(c), "Invalid JSON exponent");
    }
    next
}

unconstrained fn parse_hint<let N: u32, let T: u32>(body: [u8; N], len: u32) -> Json<T> {
    assert((len > 0) & (len <= N), "JSON byte limit");
    let empty = Node { kind: 0, start: 0, end: 0, parent: NONE, ordinal: 0, key: NONE, children: 0 };
    let mut nodes = [empty; T];
    let mut count = 0;
    let mut containers = [NONE; 33];
    let mut keys = [NONE; 33];
    // 0/1/2: array first/value/comma; 3/4/5/6/7: object first/key/colon/value/comma.
    // 8/9: document value/done. Separating first from value rejects trailing commas.
    let mut states: [u8; 33] = [0; 33];
    states[0] = 8;
    let mut depth: u32 = 0;
    let mut mode: u8 = 0;
    let mut active: u32 = 0;
    let mut string = string_start();
    let mut numeric: u8 = 0;
    let mut literal = [0; 5];
    let mut literal_len: u32 = 0;
    let mut literal_pos: u32 = 0;

    for i in 0..N {
        if i < len {
            let c = body[i];
            let mut grammar = mode == 0;
            if mode == STRING {
                let (next, closed) = string_byte(string, c);
                string = next;
                if closed {
                    nodes[active].end = i + 1;
                    mode = 0;
                }
            } else if mode == LITERAL {
                assert(c == literal[literal_pos], "Invalid JSON literal");
                literal_pos += 1;
                if literal_pos == literal_len {
                    nodes[active].end = i + 1;
                    mode = 0;
                }
            } else if mode == NUMBER {
                if digit(c) | (c == 45) | (c == 43) | (c == 46) | (c == 101) | (c == 69) {
                    numeric = number_byte(numeric, c);
                } else {
                    assert(number_end(numeric), "Incomplete JSON number");
                    nodes[active].end = i;
                    mode = 0;
                    grammar = true;
                }
            }

            if grammar & !whitespace(c) {
                let state = states[depth];
                if (c == 93) | (c == 125) {
                    assert(depth > 0, "Unmatched JSON delimiter");
                    let container = containers[depth];
                    if c == 93 {
                        assert((nodes[container].kind == ARRAY) & ((state == 0) | (state == 2)), "Invalid JSON array end");
                    } else {
                        assert((nodes[container].kind == OBJECT) & ((state == 3) | (state == 7)), "Invalid JSON object end");
                    }
                    nodes[container].end = i + 1;
                    depth -= 1;
                } else if c == 44 {
                    assert((state == 2) | (state == 7), "Unexpected JSON comma");
                    states[depth] = if state == 2 { 1 } else { 4 };
                } else if c == 58 {
                    assert(state == 5, "Unexpected JSON colon");
                    states[depth] = 6;
                } else {
                    let is_key = (state == 3) | (state == 4);
                    if is_key { assert(c == 34, "JSON object key must be a string"); }
                    else { assert((state == 0) | (state == 1) | (state == 6) | (state == 8), "Unexpected JSON value"); }
                    assert(count < T, "JSON token limit");
                    let parent = containers[depth];
                    let mut ordinal = 0;
                    let mut key = NONE;
                    if depth > 0 {
                        ordinal = nodes[parent].children;
                        if !is_key {
                            nodes[parent].children += 1;
                            if nodes[parent].kind == OBJECT { key = keys[depth]; }
                        }
                    }
                    let kind = if is_key { KEY } else if c == 91 { ARRAY } else if c == 123 { OBJECT }
                        else if c == 34 { STRING } else if (c == 45) | digit(c) { NUMBER } else { LITERAL };
                    nodes[count] = Node { kind, start: i, end: 0, parent, ordinal, key, children: 0 };
                    active = count;
                    count += 1;
                    if is_key {
                        keys[depth] = active;
                        states[depth] = 5;
                    } else {
                        states[depth] = if state == 8 { 9 } else if state == 6 { 7 } else { 2 };
                    }
                    if (kind == ARRAY) | (kind == OBJECT) {
                        assert(depth < 32, "JSON nesting limit");
                        depth += 1;
                        containers[depth] = active;
                        states[depth] = if kind == ARRAY { 0 } else { 3 };
                    } else if (kind == STRING) | (kind == KEY) {
                        mode = STRING;
                    } else if kind == NUMBER {
                        mode = NUMBER;
                        numeric = number_start(c);
                    } else {
                        assert((c == 116) | (c == 102) | (c == 110), "Invalid JSON token");
                        literal = if c == 116 { [116, 114, 117, 101, 0] }
                            else if c == 102 { [102, 97, 108, 115, 101] } else { [110, 117, 108, 108, 0] };
                        literal_len = if c == 102 { 5 } else { 4 };
                        literal_pos = 1;
                        mode = LITERAL;
                    }
                }
            }
        }
    }
    if mode == NUMBER {
        assert(number_end(numeric), "Incomplete JSON number");
        nodes[active].end = len;
        mode = 0;
    }
    assert((mode == 0) & (depth == 0) & (states[0] == 9), "Incomplete JSON document");
    Json { nodes, count }
}


fn verify_parse_keys<let N: u32, let T: u32>(body: [u8; N], len: u32, json: Json<T>, ascii_key_parent: u32) {
    assert((len > 0) & (len <= N), "JSON byte limit");
    assert((json.count > 0) & (json.count <= T), "JSON token count");
    // Canonical padding constrains unused hint outputs. Active fields are bound
    // to the actual byte stream below; bounds never replace those checks.
    for t in 0..T {
        let node = json.nodes[t];
        if t < json.count {
            assert((node.kind >= ARRAY) & (node.kind <= KEY), "JSON node kind");
            assert((node.start < node.end) & (node.end <= len), "JSON node span");
            assert((node.ordinal < T) & (node.children < T), "JSON node counts");
            if t == 0 { assert(node.parent == NONE, "JSON root parent"); }
            else { assert(node.parent < t, "JSON parent order"); }
            assert((node.key == NONE) | (node.key < t), "JSON key order");
        } else {
            assert((node.kind == 0) & (node.start == 0) & (node.end == 0), "JSON padding");
            assert((node.parent == NONE) & (node.ordinal == 0), "JSON padding");
            assert((node.key == NONE) & (node.children == 0), "JSON padding");
        }
    }
    // Mutable state is scalar. The node table is read-only ROM; a closed
    // container restores its parent and ordinal already checked on push.
    let mut count: u32 = 0;
    let mut container: u32 = NONE;
    let mut ordinal: u32 = 0;
    let mut key: u32 = NONE;
    // 0/1/2: array first/value/comma; 3/4/5/6/7: object first/key/colon/value/comma.
    // 8/9: document value/done. First/value separation rejects trailing commas.
    let mut state: u8 = 8;
    let mut depth: u32 = 0;
    let mut mode: u8 = 0;
    let mut active: u32 = 0;
    let mut require_ascii_string = false;
    let mut string = string_start();
    let mut numeric: u8 = 0;
    let mut literal = [0; 5];
    let mut literal_len: u32 = 0;
    let mut literal_pos: u32 = 0;

    for i in 0..N {
        if i < len {
            let c = body[i];
            let mut grammar = mode == 0;
            if mode == STRING {
                if require_ascii_string {
                    assert((c >= 32) & (c < 127) & (c != 92), "Unsupported escaped or non-ASCII selected field");
                }
                let (next, closed) = string_byte(string, c);
                string = next;
                if closed {
                    assert(json.nodes[active].end == i + 1, "JSON primitive end");
                    mode = 0;
                }
            } else if mode == LITERAL {
                assert(c == literal[literal_pos], "Invalid JSON literal");
                literal_pos += 1;
                if literal_pos == literal_len {
                    assert(json.nodes[active].end == i + 1, "JSON primitive end");
                    mode = 0;
                }
            } else if mode == NUMBER {
                if digit(c) | (c == 45) | (c == 43) | (c == 46) | (c == 101) | (c == 69) {
                    numeric = number_byte(numeric, c);
                } else {
                    assert(number_end(numeric), "Incomplete JSON number");
                    assert(json.nodes[active].end == i, "JSON primitive end");
                    mode = 0;
                    grammar = true;
                }
            }

            if grammar & !whitespace(c) {
                if (c == 93) | (c == 125) {
                    assert(depth > 0, "Unmatched JSON delimiter");
                    let closing = json.nodes[container];
                    if c == 93 {
                        assert((closing.kind == ARRAY) & ((state == 0) | (state == 2)), "Invalid JSON array end");
                    } else {
                        assert((closing.kind == OBJECT) & ((state == 3) | (state == 7)), "Invalid JSON object end");
                    }
                    assert(closing.end == i + 1, "JSON container end");
                    assert(closing.children == ordinal, "JSON child count");
                    container = closing.parent;
                    ordinal = if container == NONE { 0 } else { closing.ordinal + 1 };
                    state = if container == NONE { 9 }
                        else if json.nodes[container].kind == ARRAY { 2 } else { 7 };
                    depth -= 1;
                } else if c == 44 {
                    assert((state == 2) | (state == 7), "Unexpected JSON comma");
                    state = if state == 2 { 1 } else { 4 };
                } else if c == 58 {
                    assert(state == 5, "Unexpected JSON colon");
                    state = 6;
                } else {
                    let is_key = (state == 3) | (state == 4);
                    if is_key { assert(c == 34, "JSON object key must be a string"); }
                    else { assert((state == 0) | (state == 1) | (state == 6) | (state == 8), "Unexpected JSON value"); }
                    assert(count < json.count, "JSON missing node");
                    let expected_key = if state == 6 { key } else { NONE };
                    let kind = if is_key { KEY } else if c == 91 { ARRAY } else if c == 123 { OBJECT }
                        else if c == 34 { STRING } else if (c == 45) | digit(c) { NUMBER } else { LITERAL };
                    let node = json.nodes[count];
                    assert((node.kind == kind) & (node.start == i), "JSON node start");
                    assert((node.parent == container) & (node.ordinal == ordinal), "JSON node path");
                    assert(node.key == expected_key, "JSON key association");
                    if (kind != ARRAY) & (kind != OBJECT) {
                        assert(node.children == 0, "JSON primitive children");
                    }
                    active = count;
                    count += 1;
                    if is_key {
                        key = active;
                        state = 5;
                    } else {
                        state = if state == 8 { 9 } else if state == 6 { 7 } else { 2 };
                        if container != NONE { ordinal += 1; }
                    }
                    if (kind == ARRAY) | (kind == OBJECT) {
                        assert(depth < 32, "JSON nesting limit");
                        depth += 1;
                        container = active;
                        ordinal = 0;
                        state = if kind == ARRAY { 0 } else { 3 };
                    } else if (kind == STRING) | (kind == KEY) {
                        require_ascii_string = (kind == KEY) & (container == ascii_key_parent);
                        if require_ascii_string {
                            assert(node.end - node.start <= 130, "Selected JSON string byte limit");
                        }
                        mode = STRING;
                    } else if kind == NUMBER {
                        mode = NUMBER;
                        numeric = number_start(c);
                    } else {
                        assert((c == 116) | (c == 102) | (c == 110), "Invalid JSON token");
                        literal = if c == 116 { [116, 114, 117, 101, 0] }
                            else if c == 102 { [102, 97, 108, 115, 101] } else { [110, 117, 108, 108, 0] };
                        literal_len = if c == 102 { 5 } else { 4 };
                        literal_pos = 1;
                        mode = LITERAL;
                    }
                }
            }
        }
    }
    if mode == NUMBER {
        assert(number_end(numeric), "Incomplete JSON number");
        assert(json.nodes[active].end == len, "JSON primitive end");
        mode = 0;
    }
    assert((mode == 0) & (depth == 0) & (state == 9), "Incomplete JSON document");
    assert(count == json.count, "JSON unconsumed nodes");
}


fn verify_parse<let N: u32, let T: u32>(body: [u8; N], len: u32, json: Json<T>) {
    verify_parse_keys(body, len, json, NONE);
}

fn parse_with_key_policy<let N: u32, let T: u32>(body: [u8; N], len: u32, ascii_key_parent: u32) -> Json<T> {
    // Safety: verify_parse_keys binds every active node field to a complete lexical
    // and structural traversal, and constrains unused hint padding.
    let json = unsafe { parse_hint::<N, T>(body, len) };
    verify_parse_keys(body, len, json, ascii_key_parent);
    json
}

fn parse<let N: u32, let T: u32>(body: [u8; N], len: u32) -> Json<T> {
    parse_with_key_policy(body, len, NONE)
}

fn child<let T: u32>(json: Json<T>, parent: u32, ordinal: u32) -> u32 {
    let mut found = NONE;
    for i in 0..T {
        if (i < json.count) & (json.nodes[i].kind != KEY) & (json.nodes[i].parent == parent) & (json.nodes[i].ordinal == ordinal) {
            assert(found == NONE, "Ambiguous JSON child");
            found = i;
        }
    }
    assert(found != NONE, "Missing JSON child");
    found
}

fn raw_eq<let N: u32, let M: u32>(body: [u8; N], node: Node, expected: [u8; M]) -> bool {
    let mut same = node.end - node.start == M;
    for i in 0..M {
        if node.start + i < N { same = same & (body[node.start + i] == expected[i]); }
        else { same = false; }
    }
    same
}

fn string_eq<let N: u32, let M: u32>(body: [u8; N], node: Node, expected: [u8; M]) -> bool {
    let mut same = ((node.kind == STRING) | (node.kind == KEY)) & (node.end - node.start == M + 2);
    for i in 0..M {
        if node.start + 1 + i < N { same = same & (body[node.start + 1 + i] == expected[i]); }
        else { same = false; }
    }
    same
}

fn ascii_string<let N: u32, let M: u32>(body: [u8; N], node: Node) -> ([u8; M], u32) {
    assert((node.kind == STRING) | (node.kind == KEY), "Expected JSON string");
    let len = node.end - node.start - 2;
    assert(len <= M, "Selected JSON string limit");
    let mut output = [0; M];
    for i in 0..M {
        if i < len {
            let c = body[node.start + 1 + i];
            assert((c >= 32) & (c < 127) & (c != 92), "Unsupported escaped or non-ASCII selected field");
            output[i] = c;
        }
    }
    (output, len)
}

fn valid_email(email: [u8; 254], len: u32) {
    assert(len > 0, "Empty Google email");
    let punctuation = ".!#$%&'*+/=?^_`{|}~-".as_bytes();
    let mut at = NONE;
    let mut dot = NONE;
    for i in 0..254 {
        if i < len {
            let c = email[i];
            if c == 64 {
                assert((at == NONE) & (i > 0), "Invalid Google email");
                at = i;
            } else if at == NONE {
                let mut allowed = alpha(c) | digit(c);
                for j in 0..20 { allowed = allowed | (c == punctuation[j]); }
                assert(allowed, "Invalid Google email local part");
            } else {
                assert(alpha(c) | digit(c) | (c == 46) | (c == 45), "Invalid Google email domain");
                if c == 46 { dot = i; }
            }
        }
    }
    assert((at != NONE) & (dot != NONE), "Invalid Google email");
    assert((dot > at + 1) & (len >= dot + 3), "Invalid Google email suffix");
    for i in 0..254 { if (i > dot) & (i < len) { assert(alpha(email[i]), "Invalid Google email suffix"); } }
    let suffix = ".gserviceaccount.com".as_bytes();
    let mut service_account = len >= 20;
    if len >= 20 {
        for i in 0..20 {
            let c = email[len - 20 + i];
            let lower = if (c >= 65) & (c <= 90) { c + 32 } else { c };
            service_account = service_account & (lower == suffix[i]);
        }
    }
    assert(!service_account, "Service account is not a Google user");
}

// Field syntax only; authenticated row selection and account flags are bound
// by the caller. Scope hashing separately enforces canonical zero padding.
pub fn validate_identity(value: Identity) {
    assert(value.email_len <= 254, "Google email byte limit");
    valid_email(value.email, value.email_len);
    assert(value.id_len > 0, "Empty Google account ID");
    assert(value.id_len <= 64, "Google account ID byte limit");
    for i in 0..64 { if i < value.id_len { assert(digit(value.id[i]), "Invalid Google account ID"); } }
}

pub fn identity<let N: u32>(body: [u8; N], len: u32, account: u32) -> Identity {
    let json: Json<512> = parse(body, len);
    assert((json.nodes[0].kind == ARRAY) & (json.nodes[0].children == 2), "Invalid ListAccounts root");
    assert(string_eq(body, json.nodes[child(json, 0, 0)], "gaia.l.a.r".as_bytes()), "Invalid ListAccounts marker");
    let accounts = child(json, 0, 1);
    assert((json.nodes[accounts].kind == ARRAY) & (json.nodes[accounts].children <= 10), "Invalid ListAccounts accounts");
    assert(account < json.nodes[accounts].children, "Google account index out of range");
    let selected = child(json, accounts, account);
    assert((json.nodes[selected].kind == ARRAY) & (json.nodes[selected].children >= 16), "Invalid Google account array");
    assert(string_eq(body, json.nodes[child(json, selected, 0)], "gaia.l.a".as_bytes()), "Invalid Google account marker");
    assert(raw_eq(body, json.nodes[child(json, selected, 9)], "1".as_bytes()), "Google account is not signed in");
    assert(raw_eq(body, json.nodes[child(json, selected, 15)], "1".as_bytes()), "Google account is not verified");
    let invalid = json.nodes[child(json, selected, 14)];
    assert(raw_eq(body, invalid, "0".as_bytes()) | raw_eq(body, invalid, "null".as_bytes()), "Invalid Google account state");
    let (email, email_len): ([u8; 254], u32) = ascii_string(body, json.nodes[child(json, selected, 3)]);
    let (id, id_len): ([u8; 64], u32) = ascii_string(body, json.nodes[child(json, selected, 10)]);
    let value = Identity { email, email_len, id, id_len };
    validate_identity(value);
    value
}

fn decimal<let N: u32>(bytes: [u8; N], start: u32, len: u32) -> u32 {
    let mut result = 0;
    for i in 0..4 {
        if i < len { assert(digit(bytes[start + i]), "Invalid timestamp digit"); result = result * 10 + (bytes[start + i] - 48) as u32; }
    }
    result
}

fn timestamp_day(bytes: [u8; 30], len: u32, cutoff_ms: u64, window_days: u32) -> u32 {
    assert((len == 20) | ((len >= 22) & (len <= 30)), "Invalid timestamp length");
    assert((bytes[4] == 45) & (bytes[7] == 45) & (bytes[10] == 84) & (bytes[13] == 58) & (bytes[16] == 58) & (bytes[len - 1] == 90),
        "Invalid UTC timestamp");
    let year = decimal(bytes, 0, 4);
    let month = decimal(bytes, 5, 2);
    let day = decimal(bytes, 8, 2);
    let hour = decimal(bytes, 11, 2);
    let minute = decimal(bytes, 14, 2);
    let second = decimal(bytes, 17, 2);
    assert((year >= 1970) & (month >= 1) & (month <= 12) & (hour < 24) & (minute < 60) & (second < 60), "Invalid calendar timestamp");
    let leap = (year % 4 == 0) & ((year % 100 != 0) | (year % 400 == 0));
    let months: [u32; 12] = [31, 28 + leap as u32, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    assert((day >= 1) & (day <= months[month - 1]), "Invalid calendar day");
    let prior = year - 1;
    let mut days = 365 * (year - 1970) + (prior / 4 - 1969 / 4) - (prior / 100 - 1969 / 100) + (prior / 400 - 1969 / 400);
    for i in 0..12 { if i + 1 < month { days += months[i]; } }
    days += day - 1;
    let seconds = days as u64 * 86400 + hour as u64 * 3600 + minute as u64 * 60 + second as u64;
    let mut nanos: u32 = 0;
    if len > 20 {
        assert(bytes[19] == 46, "Invalid timestamp fraction");
        for i in 0..9 {
            nanos *= 10;
            if i + 20 < len - 1 { assert(digit(bytes[i + 20]), "Invalid timestamp fraction"); nanos += (bytes[i + 20] - 48) as u32; }
        }
    }
    let duration = window_days as u64 * 86400000;
    let lower = if cutoff_ms >= duration { cutoff_ms - duration } else { 0 };
    assert((seconds > lower / 1000) | ((seconds == lower / 1000) & (nanos as u64 >= lower % 1000 * 1000000)), "Timestamp before window");
    assert((seconds < cutoff_ms / 1000) | ((seconds == cutoff_ms / 1000) & (nanos as u64 <= cutoff_ms % 1000 * 1000000)), "Timestamp after window");
    year * 10000 + month * 100 + day
}

pub fn validate_time_window(cutoff_ms: u64, window_days: u32) {
    // Same Date/parameter bound as the existing GCP scope validator.
    assert(cutoff_ms <= 8640000000000000, "Invalid cutoff");
    assert((window_days == 7) | (window_days == 30) | (window_days == 90), "Invalid time window");
}

// Validates a complete, unescaped JSON timestamp string without a JSON AST.
// Exact dates stay private when the caller exposes only this predicate.
pub fn timestamp_atom<let N: u32>(bytes: [u8; N], len: u32, cutoff_ms: u64, window_days: u32) {
    validate_time_window(cutoff_ms, window_days);
    assert((len >= 22) & (len <= 32) & (len <= N), "JSON timestamp byte limit");
    assert((bytes[0] == 34) & (bytes[len - 1] == 34), "Expected JSON timestamp string");
    let mut value = [0; 30];
    for i in 0..30 {
        if i < len - 2 { value[i] = bytes[i + 1]; }
    }
    let _ = timestamp_day(value, len - 2, cutoff_ms, window_days);
}

pub fn group_response<let N: u32>(body: [u8; N], len: u32, http_status: u32, cutoff_ms: u64, window_days: u32) -> Observation {
    validate_time_window(cutoff_ms, window_days);
    // A sole root "error" member has token positions root=0, key=1, object=2.
    // The validated traversal and assertions below bind this position; the byte
    // lexer checks its immediate keys once instead of rescanning every key.
    let ascii_key_parent = if http_status == 403 { 2 } else { NONE };
    let json: Json<128> = parse_with_key_policy(body, len, ascii_key_parent);
    assert(json.nodes[0].kind == OBJECT, "Group response must be an object");
    let mut result = Observation { status: 2, day: 0 };
    if http_status == 200 {
        assert(json.nodes[0].children <= 1, "Unexpected projected response keys");
        if json.nodes[0].children == 1 {
            let entries = child(json, 0, 0);
            assert(string_eq(body, json.nodes[json.nodes[entries].key], "entries".as_bytes()), "Unexpected projected response key");
            assert((json.nodes[entries].kind == ARRAY) & (json.nodes[entries].children <= 1), "Expected at most one projected entry");
            if json.nodes[entries].children == 1 {
                let entry = child(json, entries, 0);
                assert((json.nodes[entry].kind == OBJECT) & (json.nodes[entry].children == 1), "Unexpected projected entry keys");
                let timestamp = child(json, entry, 0);
                assert(string_eq(body, json.nodes[json.nodes[timestamp].key], "timestamp".as_bytes()), "Unexpected projected entry key");
                let (value, value_len): ([u8; 30], u32) = ascii_string(body, json.nodes[timestamp]);
                result = Observation { status: 1, day: timestamp_day(value, value_len, cutoff_ms, window_days) };
            }
        }
    } else {
        assert(http_status == 403, "Unsupported group HTTP status");
        assert(json.nodes[0].children == 1, "Unexpected permission response keys");
        let error = child(json, 0, 0);
        assert(error == 2, "Unexpected permission error position");
        assert(string_eq(body, json.nodes[json.nodes[error].key], "error".as_bytes()) & (json.nodes[error].kind == OBJECT), "Expected permission error object");
        let mut codes = 0;
        let mut statuses = 0;
        let mut code_index = 0;
        let mut status_index = 0;
        for i in 0..128 {
            if (i < json.count) & (json.nodes[i].parent == error) & (json.nodes[i].kind != KEY) {
                let key = json.nodes[json.nodes[i].key];
                // Immediate error keys were already checked as literal ASCII by
                // the byte lexer, so escaped duplicate names cannot alias these.
                if string_eq(body, key, "code".as_bytes()) {
                    codes += 1;
                    code_index = i;
                }
                if string_eq(body, key, "status".as_bytes()) {
                    statuses += 1;
                    status_index = i;
                }
            }
        }
        assert((codes == 1) & (statuses == 1), "Missing or duplicate permission fields");
        assert(raw_eq(body, json.nodes[code_index], "403".as_bytes()), "Wrong permission error code");
        assert(string_eq(body, json.nodes[status_index], "PERMISSION_DENIED".as_bytes()), "Wrong permission error status");
        result = Observation { status: 3, day: 0 };
    }
    result
}

#[test]
fn identity_uses_the_selected_array_position() {
    let body = "[\"gaia.l.a.r\",[[\"gaia.l.a\",null,\"Private name\",\"first@example.test\",\"https://photo.test/a\",null,null,null,null,1,\"123\",null,null,null,null,1],[\"gaia.l.a\",null,\"Other name\",\"second@example.test\",null,null,null,null,null,1,\"456\",null,null,null,0,1]]]".as_bytes();
    let first = identity(body, body.len(), 0);
    let second = identity(body, body.len(), 1);
    assert((first.email_len == 18) & (second.email_len == 19));
    assert((first.email[0] == 102) & (second.email[0] == 115));
    assert((first.id[0] == 49) & (second.id[0] == 52));
}

#[test]
fn arbitrary_skipped_values_are_structurally_checked() {
    let body = "[\"gaia.l.a.r\",[[\"gaia.l.a\",{\"irrelevant\":[true,false,null,-1.25e+2]},\"A \\\"quoted\\\" name\",\"user-name@example.test\",\"https:\\/\\/photo.test\\u002fa\",null,null,null,null,1,\"123\",null,null,null,null,1]]]".as_bytes();
    let selected = identity(body, body.len(), 0);
    assert(selected.email_len == 22);
}

#[test]
fn accepts_escaped_backslash_and_raw_utf8_in_skipped_strings() {
    let escaped = "[\"\\\\\",\"\\uD83D\\uDE00\"]".as_bytes();
    let json: Json<16> = parse(escaped, escaped.len());
    assert(json.nodes[0].children == 2);
    let utf8 = [91, 34, 240, 159, 152, 128, 34, 93];
    let json: Json<16> = parse(utf8, utf8.len());
    assert(json.nodes[0].children == 1);
}

#[test(should_fail_with = "Invalid Google account array")]
fn nested_lookalike_account_cannot_replace_selected_account() {
    let body = "[\"gaia.l.a.r\",[{\"hidden\":[\"gaia.l.a\",null,null,\"user@example.test\",null,null,null,null,null,1,\"123\",null,null,null,null,1]}]]".as_bytes();
    let _ = identity(body, body.len(), 0);
}

#[test(should_fail_with = "Google account is not signed in")]
fn remembered_account_is_not_signed_in() {
    let body = "[\"gaia.l.a.r\",[[\"gaia.l.a\",null,null,\"user@example.test\",null,null,null,null,null,0,\"123\",null,null,null,null,1]]]".as_bytes();
    let _ = identity(body, body.len(), 0);
}

#[test(should_fail_with = "Google account is not verified")]
fn unverified_account_is_rejected() {
    let body = "[\"gaia.l.a.r\",[[\"gaia.l.a\",null,null,\"user@example.test\",null,null,null,null,null,1,\"123\",null,null,null,null,0]]]".as_bytes();
    let _ = identity(body, body.len(), 0);
}

#[test(should_fail_with = "Unsupported escaped or non-ASCII selected field")]
fn escaped_selected_email_is_explicitly_unsupported() {
    let body = "[\"gaia.l.a.r\",[[\"gaia.l.a\",null,null,\"user\\u0040example.test\",null,null,null,null,null,1,\"123\",null,null,null,null,1]]]".as_bytes();
    let _ = identity(body, body.len(), 0);
}

#[test(should_fail_with = "Service account is not a Google user")]
fn service_account_cannot_be_used_as_user() {
    let body = "[\"gaia.l.a.r\",[[\"gaia.l.a\",null,null,\"user@project.iam.gserviceaccount.com\",null,null,null,null,null,1,\"123\",null,null,null,null,1]]]".as_bytes();
    let _ = identity(body, body.len(), 0);
}

#[test]
fn projected_positive_and_both_empty_forms() {
    let positive = " { \"entries\" : [ { \"timestamp\" : \"2023-12-31T12:00:00.123456789Z\" } ] } ".as_bytes();
    let observed = group_response(positive, positive.len(), 200, 1704067200000, 7);
    assert((observed.status == 1) & (observed.day == 20231231));
    let empty = "{}".as_bytes();
    let absent = group_response(empty, empty.len(), 200, 1704067200000, 7);
    assert((absent.status == 2) & (absent.day == 0));
    let empty_entries = "{\"entries\":[]}".as_bytes();
    let absent = group_response(empty_entries, empty_entries.len(), 200, 1704067200000, 7);
    assert((absent.status == 2) & (absent.day == 0));
}

#[test]
fn permission_error_keeps_private_message_and_details_hidden() {
    let denied = "{\"error\":{\"message\":\"Private project: \\\"secret\\\"\",\"details\":[{\"reason\":\"IAM_PERMISSION_DENIED\"}],\"status\":\"PERMISSION_DENIED\",\"code\":403}}".as_bytes();
    let result = group_response(denied, denied.len(), 403, 1704067200000, 7);
    assert((result.status == 3) & (result.day == 0));
}

#[test(should_fail_with = "Unexpected projected response keys")]
fn duplicate_entries_cannot_hide_a_positive() {
    let body = "{\"entries\":[],\"entries\":[{\"timestamp\":\"2023-12-31T12:00:00Z\"}]}".as_bytes();
    let _ = group_response(body, body.len(), 200, 1704067200000, 7);
}

#[test(should_fail_with = "Unexpected projected entry keys")]
fn duplicate_timestamps_are_rejected() {
    let body = "{\"entries\":[{\"timestamp\":\"2023-12-31T12:00:00Z\",\"timestamp\":\"2024-01-01T00:00:00Z\"}]}".as_bytes();
    let _ = group_response(body, body.len(), 200, 1704067200000, 7);
}

#[test(should_fail_with = "Missing or duplicate permission fields")]
fn duplicate_permission_status_is_rejected() {
    let body = "{\"error\":{\"code\":403,\"status\":\"PERMISSION_DENIED\",\"status\":\"PERMISSION_DENIED\"}}".as_bytes();
    let _ = group_response(body, body.len(), 403, 1704067200000, 7);
}

#[test(should_fail_with = "Unsupported escaped or non-ASCII selected field")]
fn escaped_duplicate_permission_key_is_rejected() {
    let body = "{\"error\":{\"code\":403,\"status\":\"PERMISSION_DENIED\",\"\\u0073tatus\":\"UNAUTHENTICATED\"}}".as_bytes();
    let _ = group_response(body, body.len(), 403, 1704067200000, 7);
}

#[test(should_fail_with = "Wrong permission error status")]
fn other_403_errors_do_not_claim_permission_denied() {
    let body = "{\"error\":{\"code\":403,\"status\":\"RESOURCE_EXHAUSTED\"}}".as_bytes();
    let _ = group_response(body, body.len(), 403, 1704067200000, 7);
}

#[test(should_fail_with = "Invalid calendar day")]
fn normalized_invalid_dates_are_rejected() {
    let body = "{\"entries\":[{\"timestamp\":\"2023-02-29T12:00:00Z\"}]}".as_bytes();
    let _ = group_response(body, body.len(), 200, 1704067200000, 7);
}

#[test(should_fail_with = "Timestamp after window")]
fn nanosecond_after_cutoff_is_rejected() {
    let body = "{\"entries\":[{\"timestamp\":\"2024-01-01T00:00:00.000000001Z\"}]}".as_bytes();
    let _ = group_response(body, body.len(), 200, 1704067200000, 7);
}

#[test(should_fail_with = "Unexpected JSON value")]
fn trailing_second_document_is_rejected() {
    let body = "{}{}".as_bytes();
    let _: Json<16> = parse(body, body.len());
}

#[test(should_fail_with = "Invalid JSON array end")]
fn trailing_array_comma_is_rejected() {
    let body = "[1,]".as_bytes();
    let _: Json<16> = parse(body, body.len());
}

#[test(should_fail_with = "Invalid JSON escape")]
fn arbitrary_string_escape_is_rejected() {
    let body = [91, 34, 92, 113, 34, 93];
    let _: Json<16> = parse(body, body.len());
}

#[test(should_fail_with = "Invalid JSON Unicode escape")]
fn malformed_unicode_escape_is_rejected() {
    let body = [91, 34, 92, 117, 49, 50, 120, 52, 34, 93];
    let _: Json<16> = parse(body, body.len());
}

#[test(should_fail_with = "Invalid JSON UTF-8 lead")]
fn overlong_utf8_is_rejected() {
    let body = [91, 34, 192, 128, 34, 93];
    let _: Json<16> = parse(body, body.len());
}

#[test(should_fail_with = "Invalid JSON UTF-8")]
fn utf8_cannot_hide_a_quote() {
    let body = [91, 34, 226, 34, 93];
    let _: Json<16> = parse(body, body.len());
}

#[test(should_fail_with = "Leading zero in JSON number")]
fn leading_zero_is_rejected_even_in_skipped_value() {
    let body = "[01]".as_bytes();
    let _: Json<16> = parse(body, body.len());
}

#[test(should_fail_with = "Incomplete JSON number")]
fn missing_fraction_digit_is_rejected() {
    let body = "[1.]".as_bytes();
    let _: Json<16> = parse(body, body.len());
}

#[test(should_fail_with = "Invalid JSON literal")]
fn malformed_literal_is_rejected_even_when_not_selected() {
    let body = "[truX]".as_bytes();
    let _: Json<16> = parse(body, body.len());
}

#[test(should_fail_with = "Incomplete JSON document")]
fn unterminated_string_is_rejected() {
    let body = "[\"hidden".as_bytes();
    let _: Json<16> = parse(body, body.len());
}

// These tests bypass the hint builder's own validation. A malicious prover may
// replace its outputs, so correctness relies on verify_parse alone.
#[test(should_fail_with = "JSON node path")]
fn dishonest_parent_cannot_reparent_a_value() {
    let body = "{\"a\":[1,2],\"b\":3}".as_bytes();
    let mut json = unsafe { parse_hint::<17, 16>(body, body.len()) };
    json.nodes[3].parent = 0;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "JSON node path")]
fn dishonest_ordinal_cannot_select_another_value() {
    let body = "{\"a\":[1,2],\"b\":3}".as_bytes();
    let mut json = unsafe { parse_hint::<17, 16>(body, body.len()) };
    json.nodes[4].ordinal = 0;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "JSON key association")]
fn dishonest_key_cannot_relabel_a_value() {
    let body = "{\"a\":[1,2],\"b\":3}".as_bytes();
    let mut json = unsafe { parse_hint::<17, 16>(body, body.len()) };
    json.nodes[6].key = 1;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "JSON container end")]
fn dishonest_container_end_cannot_skip_a_child() {
    let body = "{\"a\":[1,2],\"b\":3}".as_bytes();
    let mut json = unsafe { parse_hint::<17, 16>(body, body.len()) };
    json.nodes[2].end -= 1;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "JSON primitive end")]
fn dishonest_primitive_end_cannot_cover_a_delimiter() {
    let body = "{\"a\":[1,2],\"b\":3}".as_bytes();
    let mut json = unsafe { parse_hint::<17, 16>(body, body.len()) };
    json.nodes[3].end += 1;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "JSON node start")]
fn dishonest_start_cannot_choose_a_substring() {
    let body = "{\"a\":[1,2],\"b\":3}".as_bytes();
    let mut json = unsafe { parse_hint::<17, 16>(body, body.len()) };
    json.nodes[3].start -= 1;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "JSON node start")]
fn dishonest_kind_cannot_turn_a_number_into_a_string() {
    let body = "{\"a\":[1,2],\"b\":3}".as_bytes();
    let mut json = unsafe { parse_hint::<17, 16>(body, body.len()) };
    json.nodes[3].kind = STRING;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "JSON child count")]
fn dishonest_child_count_cannot_hide_an_entry() {
    let body = "{\"a\":[1,2],\"b\":3}".as_bytes();
    let mut json = unsafe { parse_hint::<17, 16>(body, body.len()) };
    json.nodes[2].children = 1;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "JSON unconsumed nodes")]
fn dishonest_extra_node_cannot_duplicate_an_entry() {
    let body = "{\"a\":[1,2],\"b\":3}".as_bytes();
    let mut json = unsafe { parse_hint::<17, 16>(body, body.len()) };
    json.nodes[7] = json.nodes[6];
    json.count = 8;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "JSON padding")]
fn dishonest_padding_is_constrained() {
    let body = "{}".as_bytes();
    let mut json = unsafe { parse_hint::<2, 16>(body, body.len()) };
    json.nodes[15].start = 1;
    verify_parse(body, body.len(), json);
}

#[test(should_fail_with = "Leading zero in JSON number")]
fn valid_hint_does_not_excuse_invalid_number_bytes() {
    let original = "[10]".as_bytes();
    let json = unsafe { parse_hint::<4, 16>(original, original.len()) };
    let changed = "[01]".as_bytes();
    verify_parse(changed, changed.len(), json);
}

#[test(should_fail_with = "Invalid JSON literal")]
fn valid_hint_does_not_excuse_invalid_literal_bytes() {
    let original = "[true]".as_bytes();
    let json = unsafe { parse_hint::<6, 16>(original, original.len()) };
    let changed = "[truX]".as_bytes();
    verify_parse(changed, changed.len(), json);
}

#[test(should_fail_with = "Invalid JSON escape")]
fn valid_hint_does_not_excuse_invalid_escape_bytes() {
    let original = "[\"\\n\"]".as_bytes();
    let json = unsafe { parse_hint::<6, 16>(original, original.len()) };
    let changed = "[\"\\x\"]".as_bytes();
    verify_parse(changed, changed.len(), json);
}

#[test]
fn permission_key_policy_does_not_restrict_nested_private_details() {
    let body = "{\"error\":{\"code\":403,\"status\":\"PERMISSION_DENIED\",\"details\":[{\"co\\u0064e\":9}],\"message\":\"Private \\u540d\"}}".as_bytes();
    assert(group_response(body, body.len(), 403, 1704067200000, 30).status == 3);
}

#[test(should_fail_with = "Unsupported escaped or non-ASCII selected field")]
fn valid_hint_cannot_bypass_immediate_permission_key_policy() {
    let mut body = "{\"error\":{\"code\":403}}".as_bytes();
    let json = unsafe { parse_hint::<22, 16>(body, body.len()) };
    body[12] = 92;
    body[13] = 110;
    verify_parse_keys(body, body.len(), json, 2);
}


#[test]
fn timestamp_atom_accepts_both_inclusive_window_edges() {
    let lower = "\"2023-12-25T00:00:00.000000000Z\"".as_bytes();
    let upper = "\"2024-01-01T00:00:00Z\"".as_bytes();
    timestamp_atom(lower, lower.len(), 1704067200000, 7);
    timestamp_atom(upper, upper.len(), 1704067200000, 7);
}

#[test(should_fail_with = "Expected JSON timestamp string")]
fn timestamp_atom_requires_quotes() {
    let value = " 2024-01-01T00:00:00Z ".as_bytes();
    timestamp_atom(value, value.len(), 1704067200000, 7);
}

#[test(should_fail_with = "Expected JSON timestamp string")]
fn timestamp_atom_rejects_trailing_bytes() {
    let value = "\"2024-01-01T00:00:00Z\",1".as_bytes();
    timestamp_atom(value, value.len(), 1704067200000, 7);
}

#[test(should_fail_with = "Invalid timestamp digit")]
fn timestamp_atom_rejects_escaped_timestamp_digits() {
    let value = "\"2024-01-01T00:00:0\\u0030Z\"".as_bytes();
    timestamp_atom(value, value.len(), 1704067200000, 7);
}

#[test(should_fail_with = "Timestamp before window")]
fn timestamp_atom_rejects_one_nanosecond_before_window() {
    let value = "\"2023-12-24T23:59:59.999999999Z\"".as_bytes();
    timestamp_atom(value, value.len(), 1704067200000, 7);
}

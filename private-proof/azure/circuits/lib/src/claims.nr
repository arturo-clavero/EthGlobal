use source::json;
use crate::activity::key_parts;
mod tests;

fn whitespace(c: u8) -> bool { (c == 32) | (c == 9) | (c == 10) | (c == 13) }
fn lower(c: u8) -> u8 { if (c >= 65) & (c <= 90) { c + 32 } else { c } }

struct State {
    grammar: u8, parts: [Field; 2], key_len: u32, selected: u8,
    seen_actor: bool, seen_tenant: bool, position: u32, string: json::StringState, consumed: u32,
}

fn initial() -> State {
    State { grammar: 0, parts: [0; 2], key_len: 0, selected: 0, seen_actor: false,
        seen_tenant: false, position: 0, string: json::string_start(), consumed: 0 }
}

fn finish(state: State) {
    assert(state.grammar == 8, "Incomplete claims object");
    assert(state.seen_actor & state.seen_tenant, "Missing claims identity");
}

fn encode(state: State) -> [u8; 83] {
    let mut bytes = [0u8; 83]; bytes[0] = state.grammar;
    for part in 0..2 {
        let value: [u8; 31] = state.parts[part].to_be_bytes();
        for i in 0..31 { bytes[1 + part * 31 + i] = value[i]; }
    }
    let counts = [state.key_len, state.position, state.consumed];
    let starts = [63u32, 70, 79];
    for count in 0..3 {
        let value: [u8; 4] = (counts[count] as Field).to_be_bytes();
        for i in 0..4 { bytes[starts[count] + i] = value[i]; }
    }
    bytes[67] = state.selected; bytes[68] = state.seen_actor as u8; bytes[69] = state.seen_tenant as u8;
    let string = json::string_state_bytes(state.string);
    for i in 0..5 { bytes[74 + i] = string[i]; }
    bytes
}

fn decode(bytes: [u8; 83]) -> State {
    assert((bytes[0] <= 8) & (bytes[67] <= 2) & (bytes[68] <= 1) & (bytes[69] <= 1), "Invalid claims state");
    let mut parts = [0 as Field; 2];
    for part in 0..2 {
        // Each 31-byte encoding is below the field modulus, so decoding is injective.
        for i in 0..31 { parts[part] = parts[part] * 256 + bytes[1 + part * 31 + i] as Field; }
    }
    let mut counts = [0u32; 3]; let starts = [63u32, 70, 79];
    for count in 0..3 {
        for i in 0..4 { counts[count] = counts[count] * 256 + bytes[starts[count] + i] as u32; }
        assert(counts[count] <= 2304, "Invalid claims state count");
    }
    let mut string = [0u8; 5]; for i in 0..5 { string[i] = bytes[74 + i]; }
    State { grammar: bytes[0], parts, key_len: counts[0], selected: bytes[67], seen_actor: bytes[68] == 1,
        seen_tenant: bytes[69] == 1, position: counts[1], string: json::string_state_from_bytes(string), consumed: counts[2] }
}

pub fn initial_bytes() -> [u8; 83] { encode(initial()) }

// The caller authenticates each native chunk and chains blinded state hashes in exact source order.
pub fn transition<let N: u32>(body: [u8; N], len: u32, before: [u8; 83], offset: u32, total: u32,
    object_id: [u8; 36], tenant: [u8; 36]) -> [u8; 83] {
    assert((N > 0) & (total > 0) & (total <= 2304) & (offset < total), "Claims total byte limit");
    assert(offset % N == 0, "Claims chunk offset");
    let expected = if total - offset < N { total - offset } else { N };
    assert(len == expected, "Claims chunk length");
    let state = decode(before);
    assert(state.consumed == offset, "Claims state offset");
    if offset == 0 { assert(before == initial_bytes(), "Claims initial state"); }
    let next = scan(body, len, state, object_id, tenant);
    if next.consumed == total { finish(next); }
    encode(next)
}

// Whole-object compatibility helper; large constrained instances remain expensive.
pub fn actor<let N: u32>(body: [u8; N], len: u32, object_id: [u8; 36], tenant: [u8; 36]) {
    finish(scan(body, len, initial(), object_id, tenant));
}

fn scan<let N: u32>(body: [u8; N], len: u32, before: State, object_id: [u8; 36], tenant: [u8; 36]) -> State {
    assert((len > 0) & (len <= N), "Claims byte limit");
    for i in 0..36 {
        if (i == 8) | (i == 13) | (i == 18) | (i == 23) {
            assert((object_id[i] == 45) & (tenant[i] == 45), "Invalid claims reference");
        } else {
            for c in [object_id[i], tenant[i]] {
                assert(((c >= 48) & (c <= 57)) | ((c >= 97) & (c <= 102)), "Invalid claims reference");
            }
        }
    }
    let actor_key = key_parts("http://schemas.microsoft.com/identity/claims/objectidentifier".as_bytes());
    let tenant_key = key_parts("http://schemas.microsoft.com/identity/claims/tenantid".as_bytes());
    let actor_value = key_parts(object_id);
    let tenant_value = key_parts(tenant);
    // 0=open, 1=first key/end, 2=key, 3=colon, 4=value, 5=string, 6=comma/end, 7=next key, 8=done.
    let mut state = before.grammar;
    let mut parts = before.parts;
    let mut key_len = before.key_len;
    let mut selected = before.selected;
    let mut seen_actor = before.seen_actor;
    let mut seen_tenant = before.seen_tenant;
    let mut position = before.position;
    let mut string = before.string;
    for i in 0..N {
        if i < len {
            let c = body[i];
            if state == 2 {
                assert((c >= 32) & (c < 127) & (c != 92), "Unsupported claims key");
                if c == 34 {
                    selected = if (key_len == 61) & (parts == actor_key) { 1 }
                        else if (key_len == 53) & (parts == tenant_key) { 2 } else { 0 };
                    if selected == 1 { assert(!seen_actor, "Duplicate claims actor"); seen_actor = true; }
                    if selected == 2 { assert(!seen_tenant, "Duplicate claims tenant"); seen_tenant = true; }
                    state = 3;
                } else {
                    if key_len < 31 { parts[0] = parts[0] * 256 + c as Field; }
                    else if key_len < 62 { parts[1] = parts[1] * 256 + c as Field; }
                    key_len += 1;
                }
            } else if state == 5 {
                let (next, closed) = json::string_byte(string, c);
                string = next;
                if closed {
                    if selected != 0 {
                        assert(position == 36, "Invalid claims identity length");
                        if selected == 1 { assert(parts == actor_value, "Wrong Activity actor"); }
                        else { assert(parts == tenant_value, "Wrong Activity tenant"); }
                    }
                    state = 6;
                } else {
                    if selected != 0 {
                        assert(position < 36, "Invalid claims identity length");
                        // Exact bounded limbs avoid private array indexing at every source byte.
                        if position < 31 { parts[0] = parts[0] * 256 + lower(c) as Field; }
                        else { parts[1] = parts[1] * 256 + lower(c) as Field; }
                    }
                    position += 1;
                }
            } else if !whitespace(c) {
                if state == 0 { assert(c == 123, "Expected claims object"); state = 1; }
                else if (state == 1) | (state == 7) {
                    if (state == 1) & (c == 125) { state = 8; }
                    else {
                        assert(c == 34, "Expected claims key");
                        parts = [0 as Field; 2]; key_len = 0; state = 2;
                    }
                } else if state == 3 { assert(c == 58, "Expected claims colon"); state = 4; }
                else if state == 4 {
                    assert(c == 34, "Expected claims string");
                    string = json::string_start(); parts = [0 as Field; 2]; position = 0; state = 5;
                } else if state == 6 {
                    assert((c == 44) | (c == 125), "Expected claims delimiter");
                    state = if c == 44 { 7 } else { 8 };
                } else { assert(false, "Trailing claims document"); }
            }
        }
    }
    State { grammar: state, parts, key_len, selected, seen_actor, seen_tenant, position, string, consumed: before.consumed + len }
}

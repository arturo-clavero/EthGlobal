use super::main;

struct Fixture {
    chunks: [[u8; 528]; 2], states: [[u8; 99]; 3], ids: [[u8; 54]; 2], total: u32,
}

fn fixture() -> Fixture {
    let prefix = "{\"padding\":\"".as_bytes();
    let suffix = "\",\"http://schemas.microsoft.com/identity/claims/objectidentifier\":\"AAAAAAAA-1111-2222-3333-444444444444\",\"http://schemas.microsoft.com/identity/claims/tenantid\":\"BBBBBBBB-1111-2222-3333-444444444444\"}".as_bytes();
    let mut body = [0u8; 768]; let total = 516 + suffix.len();
    for i in 0..516 { body[i] = if i < prefix.len() { prefix[i] } else { 97 }; }
    for i in 0..suffix.len() { body[516 + i] = suffix[i]; }
    body[511] = 240; body[512] = 159; body[513] = 152; body[514] = 128;
    let actor = "aaaaaaaa-1111-2222-3333-444444444444".as_bytes();
    let tenant = "bbbbbbbb-1111-2222-3333-444444444444".as_bytes();
    let mut chunks = [[0u8; 528]; 2]; let mut states = [[0u8; 99]; 3];
    let mut state = azure::claims::initial_bytes();
    for i in 0..83 { states[0][i] = state[i]; }
    for part in 0..2 {
        let offset = part * 512; let length = if part == 0 { 512 } else { total - 512 };
        let mut chunk = [0u8; 512];
        for i in 0..512 { if i < length { chunk[i] = body[offset + i]; chunks[part][i] = chunk[i]; } }
        for i in 0..16 { chunks[part][length + i] = (17 + part) as u8; }
        state = azure::claims::transition(chunk, length, state, offset, total, actor, tenant);
        for i in 0..83 { states[part + 1][i] = state[i]; }
    }
    for part in 0..3 { for i in 83..99 { states[part][i] = (31 + part) as u8; } }
    let values = ["\"aaaaaaaa-1111-2222-3333-444444444444\"".as_bytes(), "\"bbbbbbbb-1111-2222-3333-444444444444\"".as_bytes()];
    let mut ids = [[0u8; 54]; 2];
    for part in 0..2 {
        for i in 0..38 { ids[part][i] = values[part][i]; }
        for i in 38..54 { ids[part][i] = (71 + part) as u8; }
    }
    Fixture { chunks, states, ids, total }
}

fn hashes(fixture: Fixture, part: u32) -> [[u8; 32]; 5] {
    let length = if part == 0 { 512 } else { fixture.total - 512 };
    [sha256::sha256_var(fixture.chunks[part], length + 16), sha256::sha256_var(fixture.states[part], 99),
        sha256::sha256_var(fixture.states[part + 1], 99), sha256::sha256_var(fixture.ids[0], 54), sha256::sha256_var(fixture.ids[1], 54)]
}

fn verify(fixture: Fixture, part: u32) {
    let length = if part == 0 { 512 } else { fixture.total - 512 };
    main(hashes(fixture, part), length, part * 512, fixture.total, fixture.chunks[part],
        [fixture.states[part], fixture.states[part + 1]], fixture.ids);
}

#[test]
fn authenticates_complete_chain_with_split_utf8_and_private_states() {
    let fixture = fixture();
    assert(hashes(fixture, 0)[2] == hashes(fixture, 1)[1]);
    verify(fixture, 0); verify(fixture, 1);
}

#[test(should_fail_with = "Transcript commitment mismatch")]
fn rejects_tampered_native_chunk() {
    let mut fixture = fixture(); let expected = hashes(fixture, 0); fixture.chunks[0][20] = 98;
    main(expected, 512, 0, fixture.total, fixture.chunks[0], [fixture.states[0], fixture.states[1]], fixture.ids);
}

#[test(should_fail_with = "Claims state transition mismatch")]
fn rejects_authenticated_wrong_outgoing_state() {
    let mut fixture = fixture(); fixture.states[1][68] = 1; verify(fixture, 0);
}

#[test(should_fail_with = "Claims state offset")]
fn rejects_reordered_state() {
    let mut fixture = fixture(); fixture.states[1] = fixture.states[0]; verify(fixture, 1);
}

#[test(should_fail_with = "Wrong Activity actor")]
fn rejects_changed_derived_identity() {
    let mut fixture = fixture(); fixture.ids[0] = fixture.ids[1]; verify(fixture, 1);
}

//! Tests for the revealed-size ceiling (`TLSN_MAX_REVEAL_BLOCKS`): the
//! AES-block count, the prove-request count, and the refusal of a
//! `reveal_config` over the ceiling on `/session`. Local servers only.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;

use crate::reveal::{self, aes_blocks, request_blocks, reveal_config_blocks, REVEAL_TOO_LARGE};
use crate::settings::Settings;

// ---------------------------------------------------------------------------
// Counting
// ---------------------------------------------------------------------------

#[test]
fn blocks_are_counted_by_offset() {
    assert_eq!(aes_blocks(Vec::<std::ops::Range<usize>>::new()), 0);
    assert_eq!(aes_blocks([0..1]), 1);
    assert_eq!(aes_blocks([0..16]), 1);
    assert_eq!(aes_blocks([0..17]), 2);
    assert_eq!(aes_blocks([15..17]), 2);
    // 80 aligned bytes = 5 blocks; the same 80 bytes shifted by 8 touch 6.
    assert_eq!(aes_blocks([160..240]), 5);
    assert_eq!(aes_blocks([168..248]), 6);
}

#[test]
fn shared_and_overlapping_blocks_count_once() {
    // Two ranges in one block, unsorted, plus an overlap and a duplicate.
    assert_eq!(aes_blocks([10..12, 2..4]), 1);
    assert_eq!(aes_blocks([0..40, 20..70, 0..40]), 5);
    // Adjacent ranges that meet inside block 1.
    assert_eq!(aes_blocks([0..20, 20..32]), 2);
    // Disjoint blocks.
    assert_eq!(aes_blocks([0..16, 32..48]), 2);
}

#[test]
#[allow(clippy::reversed_empty_ranges)]
fn empty_and_inverted_ranges_count_nothing() {
    assert_eq!(aes_blocks([5..5, 9..3]), 0);
    assert_eq!(aes_blocks([9..3, 0..1]), 1);
}

#[test]
fn reveal_config_counts_both_directions() {
    // sent: blocks 0 and 1; recv: 0..84 = blocks 0-5, 6936..6946 = blocks 433-434.
    assert_eq!(
        reveal_config_blocks(&[0..10, 20..30], &[0..84, 6936..6946]),
        2 + 6 + 2
    );
}

#[test]
fn prove_request_counts_reveals_and_hash_commitments() {
    use tlsn::config::prove::ProveConfig;
    use tlsn::hash::HashAlgId;
    use tlsn::transcript::{Transcript, TranscriptCommitConfig, TranscriptCommitmentKind};

    let transcript = Transcript::new(vec![b'a'; 100], vec![b'b'; 1_000]);
    let mut builder = ProveConfig::builder(&transcript);
    builder.server_identity();
    builder.reveal_sent(&(0..10)).unwrap();
    builder.reveal_sent(&(20..30)).unwrap();
    builder.reveal_recv(&(0..84)).unwrap();
    builder.reveal_recv(&(500..520)).unwrap();
    let mut commit = TranscriptCommitConfig::builder(&transcript);
    commit.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });
    // Overlaps the revealed 500..520 (blocks 31-32), adds blocks 33-37.
    commit.commit_recv(&(510..600)).unwrap();
    // A sent commitment in a block of its own.
    commit.commit_sent(&(64..70)).unwrap();
    builder.transcript_commit(commit.build().unwrap());
    let request = builder.build().unwrap().to_request();
    // sent: block 0, block 1 (20..30) and block 4 (64..70) = 3; recv: 0..84 = 6, 500..600 = blocks 31-37 = 7.
    assert_eq!(request_blocks(&request), 3 + 6 + 7);
}

#[test]
fn ceiling_is_inclusive_and_the_message_starts_with_the_code() {
    assert_eq!(reveal::check(1_400, 1_400), None);
    let msg = reveal::check(1_401, 1_400).expect("over the ceiling");
    assert!(msg.starts_with(&format!("{REVEAL_TOO_LARGE}: ")), "{msg}");
    assert!(msg.contains("1401") && msg.contains("1400"), "{msg}");
    // A client must not read it as busy (retryable): no socket words.
    assert!(!msg.to_ascii_lowercase().contains("socket"), "{msg}");
}

#[test]
fn default_settings_are_unlimited_and_the_env_default_is_measured() {
    assert_eq!(Settings::default().max_reveal_blocks, usize::MAX);
    assert_eq!(reveal::DEFAULT_MAX_REVEAL_BLOCKS, 2_500);
}

// ---------------------------------------------------------------------------
// Over HTTP: reveal_config on /session
// ---------------------------------------------------------------------------

pub(super) type Client =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

pub(super) async fn serve(settings: Settings) -> (SocketAddr, Arc<crate::AppState>) {
    let state = Arc::new(crate::AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        config: Arc::new(crate::Config::default()),
        settings: Arc::new(settings),
    });
    let app = crate::router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (addr, state)
}

pub(super) async fn registered(addr: SocketAddr) -> Client {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/session"))
        .await
        .expect("upgrade");
    let register = serde_json::json!({
        "type": "register",
        "maxRecvData": 4096,
        "maxSentData": 1024,
        "sessionData": { "method": "TEST", "step": "A" },
    });
    ws.send(Message::Text(register.to_string().into()))
        .await
        .unwrap();
    match tokio::time::timeout(Duration::from_secs(5), ws.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => assert!(text.contains("session_registered"), "{text}"),
        other => panic!("no reply to register: {other:?}"),
    }
    ws
}

pub(super) fn reveal_config(recv: &[(usize, usize)]) -> String {
    let range = |&(start, end): &(usize, usize)| {
        serde_json::json!({ "start": start, "end": end,
            "handler": { "type": "RECV", "part": "BODY", "action": { "kind": "REVEAL" } } })
    };
    serde_json::json!({
        "type": "reveal_config",
        "sent": [],
        "recv": recv.iter().map(range).collect::<Vec<_>>(),
    })
    .to_string()
}

pub(super) async fn next_text(ws: &mut Client, wait: Duration) -> Option<String> {
    match tokio::time::timeout(wait, ws.next()).await {
        Ok(Some(Ok(Message::Text(text)))) => Some(text.as_str().to_owned()),
        _ => None,
    }
}

#[tokio::test]
async fn reveal_config_over_the_ceiling_is_refused_and_frees_the_session() {
    let (addr, state) = serve(Settings {
        max_reveal_blocks: 10,
        max_sessions: 1,
        ..Settings::default()
    })
    .await;
    let mut ws = registered(addr).await;
    assert_eq!(state.sessions.lock().await.len(), 1);
    // 11 blocks: 0..160 is 10, plus one more in another block.
    ws.send(Message::Text(reveal_config(&[(0, 160), (400, 401)]).into()))
        .await
        .unwrap();
    let reply = next_text(&mut ws, Duration::from_secs(5))
        .await
        .expect("an error reply");
    assert!(reply.contains("\"type\":\"error\""), "{reply}");
    assert!(
        reply.contains(
            "REVEAL_TOO_LARGE: the reveal touches 11 AES blocks, over the verifier limit of 10"
        ),
        "{reply}"
    );
    // The verifier task is stopped and the session is gone: the one slot is free again.
    let mut freed = false;
    for _ in 0..50 {
        if state.sessions.lock().await.is_empty() && state.settings.active_sessions() == 0 {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(freed, "the refused session still holds its slot");
    let _second = registered(addr).await;
}

#[tokio::test]
async fn reveal_config_at_the_ceiling_is_forwarded() {
    let (addr, state) = serve(Settings {
        max_reveal_blocks: 10,
        ..Settings::default()
    })
    .await;
    let mut ws = registered(addr).await;
    // Exactly 10 blocks (two ranges share block 9): accepted, so the session waits
    // for the prover (it never connects here) and sends nothing back yet.
    ws.send(Message::Text(reveal_config(&[(0, 150), (150, 160)]).into()))
        .await
        .unwrap();
    assert_eq!(next_text(&mut ws, Duration::from_millis(800)).await, None);
    assert_eq!(state.sessions.lock().await.len(), 1);
}

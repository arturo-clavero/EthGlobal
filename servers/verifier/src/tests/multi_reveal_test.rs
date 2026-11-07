//! Several proofs of one TLS session. A real Proxy-mode prover (tlsn, in
//! process) proves a local HTTPS fixture's response through `/session` +
//! `/verifier`; the verifier dials the fixture (`Settings::test_dial`) and
//! trusts its CA (`Settings::test_roots`). Each proof gets its own result
//! (`reveal_completed`, webhook) with its step and the session link; the
//! session closes on `finish`; the reveal ceiling and the memory admission
//! apply per proof; a single-proof client sees the upstream protocol
//! unchanged. Local servers only.

use std::collections::HashMap;
use std::future::IntoFuture;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::{extract::State, routing::post, Json, Router};
use futures_util::io::{AsyncReadExt as _, AsyncWriteExt as _};
use futures_util::SinkExt;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::compat::TokioAsyncReadCompatExt;
use ws_stream_tungstenite::WsStream;

use tlsn::{
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig,
    },
    connection::{DnsName, ServerName},
    prover::{state, Prover},
    webpki::{CertificateDer, RootCertStore},
    Session, SessionHandle,
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER};

use super::reveal_test::{next_text, Client};
use crate::admission::MemoryBudget;
use crate::reveal::REVEAL_TOO_LARGE;
use crate::settings::Settings;

const WAIT: Duration = Duration::from_secs(120);
const BODY: usize = 6_000;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

fn pem(label: &str, der: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(line).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out.into_bytes()
}

fn body() -> Vec<u8> {
    b"abcdefghijklmnopqrstuvwxyz0123456789\n".iter().copied().cycle().take(BODY).collect()
}

/// A local HTTPS server for `SERVER_DOMAIN` (the fixture certificate): every
/// request gets the same 200 response, then the connection closes.
async fn https_fixture() -> SocketAddr {
    let identity = native_tls::Identity::from_pkcs8(
        &pem("CERTIFICATE", SERVER_CERT_DER),
        &pem("PRIVATE KEY", SERVER_KEY_DER),
    )
    .unwrap();
    let acceptor = tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).unwrap());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                let mut request = Vec::new();
                let mut buf = [0u8; 1024];
                while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                    match tls.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => request.extend_from_slice(&buf[..n]),
                    }
                }
                let body = body();
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = tls.write_all(head.as_bytes()).await;
                let _ = tls.write_all(&body).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    addr
}

type Payloads = Arc<Mutex<Vec<Value>>>;

async fn webhook_sink() -> (String, Payloads) {
    async fn collect(State(payloads): State<Payloads>, Json(body): Json<Value>) -> &'static str {
        payloads.lock().await.push(body);
        "ok"
    }
    let payloads: Payloads = Arc::new(Mutex::new(Vec::new()));
    let app = Router::new().route("/hook", post(collect)).with_state(payloads.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}/hook"), payloads)
}

struct Verifier {
    addr: SocketAddr,
    state: Arc<crate::AppState>,
    payloads: Payloads,
}

async fn verifier(settings: Settings) -> Verifier {
    let fixture = https_fixture().await;
    let (hook, payloads) = webhook_sink().await;
    let mut webhooks = HashMap::new();
    webhooks.insert(
        "*".to_string(),
        crate::WebhookConfig {
            url: hook,
            headers: HashMap::new(),
        },
    );
    let state = Arc::new(crate::AppState {
        sessions: Arc::new(Mutex::new(HashMap::new())),
        config: Arc::new(crate::Config { webhooks }),
        settings: Arc::new(Settings {
            test_dial: Some(fixture.to_string()),
            test_roots: Some(vec![CA_CERT_DER.to_vec()]),
            ..settings
        }),
    });
    let app = crate::router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Verifier {
        addr,
        state,
        payloads,
    }
}

/// The `/session` socket after `register` and the registered session id.
async fn register(addr: SocketAddr, multi: bool, session_data: Value) -> (Client, String, Value) {
    let (mut ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/session"))
        .await
        .expect("upgrade");
    let mut register = json!({
        "type": "register",
        "maxRecvData": 16384,
        "maxSentData": 1024,
        "sessionData": session_data,
    });
    if multi {
        register["multiReveal"] = json!(true);
    }
    ws.send(Message::Text(register.to_string().into())).await.unwrap();
    let reply: Value = serde_json::from_str(&next_text(&mut ws, WAIT).await.expect("registered")).unwrap();
    assert_eq!(reply["type"], "session_registered", "{reply}");
    let sid = reply["sessionId"].as_str().unwrap().to_string();
    (ws, sid, reply)
}

/// A committed Proxy-mode prover with the fixture's response in its transcript.
async fn committed_prover(addr: SocketAddr, sid: &str) -> (Prover<state::Committed>, SessionHandle) {
    let url = format!("ws://{addr}/verifier?sessionId={sid}");
    let tcp = TcpStream::connect(addr).await.unwrap();
    let (ws, _) = async_tungstenite::client_async(url, tcp.compat()).await.unwrap();
    let session = Session::new(WsStream::new(ws));
    let (driver, mut handle) = session.split();
    tokio::spawn(driver);
    let roots = || RootCertStore {
        roots: vec![CertificateDer(CA_CERT_DER.to_vec())],
    };
    let prover = handle
        .new_prover(ProverConfig::builder().build().unwrap())
        .unwrap()
        .commit(
            ProxyTlsConfig::builder()
                .server_name(DnsName::try_from(SERVER_DOMAIN).unwrap())
                .build()
                .unwrap(),
        )
        .await
        .unwrap();
    let (mut tls, prover) = prover
        .connect(
            TlsClientConfig::builder()
                .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
                .root_store(roots())
                .build()
                .unwrap(),
        )
        .unwrap();
    let task = tokio::spawn(prover.into_future());
    tls.write_all(format!("GET /data HTTP/1.1\r\nHost: {SERVER_DOMAIN}\r\nConnection: close\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    tls.close().await.unwrap();
    let prover = task.await.unwrap().unwrap();
    assert!(prover.transcript().received().len() > BODY);
    (prover, handle)
}

fn range(start: usize, end: usize, part: &str) -> Value {
    json!({ "start": start, "end": end,
        "handler": { "type": if part == "START_LINE" { "SENT" } else { "RECV" }, "part": part, "action": { "kind": "REVEAL" } } })
}

/// One proof: reveal_config on the session socket, then the prove request.
async fn prove(
    ws: &mut Client,
    prover: &mut Prover<state::Committed>,
    sent: &[(usize, usize)],
    recv: &[(usize, usize)],
    identity: bool,
    step: Option<&str>,
) -> Value {
    let mut config = json!({
        "type": "reveal_config",
        "sent": sent.iter().map(|&(a, b)| range(a, b, "START_LINE")).collect::<Vec<_>>(),
        "recv": recv.iter().map(|&(a, b)| range(a, b, "BODY")).collect::<Vec<_>>(),
    });
    if let Some(step) = step {
        config["step"] = json!(step);
    }
    ws.send(Message::Text(config.to_string().into())).await.unwrap();
    let mut builder = ProveConfig::builder(prover.transcript());
    if identity {
        builder.server_identity();
    }
    for &(a, b) in sent {
        builder.reveal_sent(&(a..b)).unwrap();
    }
    for &(a, b) in recv {
        builder.reveal_recv(&(a..b)).unwrap();
    }
    tokio::time::timeout(WAIT, prover.prove(&builder.build().unwrap()))
        .await
        .expect("prove stalled")
        .unwrap();
    serde_json::from_str(&next_text(ws, WAIT).await.expect("a result")).unwrap()
}

async fn payloads(v: &Verifier, n: usize) -> Vec<Value> {
    for _ in 0..100 {
        if v.payloads.lock().await.len() >= n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut out = v.payloads.lock().await.clone();
    out.sort_by_key(|p| p["session"]["reveal"].as_str().unwrap_or("0").parse::<usize>().unwrap());
    out
}

async fn freed(v: &Verifier) -> bool {
    for _ in 0..100 {
        let memory = v.state.settings.memory_budget.as_ref().map_or(0, |b| b.reserved_mb());
        if v.state.sessions.lock().await.is_empty() && v.state.settings.active_sessions() == 0 && memory == 0 {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn text(results: &Value) -> Vec<String> {
    results
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["value"].as_str().unwrap().to_string())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn three_proofs_of_one_session_give_three_results_then_close() {
    let v = verifier(Settings {
        memory_budget: Some(MemoryBudget::new(2_600, Duration::from_secs(10))),
        ..Settings::default()
    })
    .await;
    // A client cannot claim the link keys: they are the verifier's.
    let (mut ws, sid, reply) = register(
        v.addr,
        true,
        json!({ "method": "TEST", "step": "P0", "proofId": "p", "revealOf": "forged", "reveal": "9" }),
    )
    .await;
    assert_eq!(reply["multiReveal"], true);
    let (mut prover, handle) = committed_prover(v.addr, &sid).await;
    let recv = prover.transcript().received().to_vec();
    let head = recv.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;

    // Proof 0: the start line and server identity.
    let sets: [(&[(usize, usize)], Vec<(usize, usize)>, Option<&str>); 3] = [
        (&[(0, 14)], vec![(0, 15), (head, head + 40)], None),
        (&[], vec![(head + 1000, head + 1080)], Some("P0w1")),
        // Shares an AES block with proof 0's (head, head + 40).
        (&[], vec![(head + 30, head + 70), (head + 4000, head + 4010)], Some("P0w2")),
    ];
    let mut ids = Vec::new();
    for (i, (sent, recv_ranges, step)) in sets.iter().enumerate() {
        let reply = prove(&mut ws, &mut prover, sent, recv_ranges, i == 0, *step).await;
        assert_eq!(reply["type"], "reveal_completed", "{reply}");
        assert_eq!(reply["reveal"], i, "{reply}");
        let id = reply["resultId"].as_str().unwrap().to_string();
        assert!(uuid::Uuid::parse_str(&id).is_ok(), "{id}");
        let mut want: Vec<String> = sent.iter().map(|&(a, b)| String::from_utf8(prover.transcript().sent()[a..b].to_vec()).unwrap()).collect();
        want.extend(recv_ranges.iter().map(|&(a, b)| String::from_utf8(recv[a..b].to_vec()).unwrap()));
        assert_eq!(text(&reply["results"]), want, "proof {i}");
        ids.push(id);
        // The session holds the largest proof's step budget (all three are in the
        // smallest bracket here), never their sum.
        assert_eq!(v.state.settings.memory_budget.as_ref().unwrap().reserved_mb(), 180);
    }
    assert_eq!(ids[0], sid, "the first result keeps the session id");
    assert!(ids[1] != ids[0] && ids[2] != ids[1] && ids[2] != ids[0]);

    ws.send(Message::Text(json!({ "type": "finish" }).to_string().into())).await.unwrap();
    prover.close().await.unwrap();
    handle.close();
    let closed: Value = serde_json::from_str(&next_text(&mut ws, WAIT).await.expect("session_closed")).unwrap();
    assert_eq!(closed, json!({ "type": "session_closed", "reveals": 3 }));
    assert!(freed(&v).await, "the session still holds its slot or memory");

    // One webhook per proof, each its own result: id, step, link, its own ranges.
    let got = payloads(&v, 3).await;
    assert_eq!(got.len(), 3);
    for (i, p) in got.iter().enumerate() {
        let session = &p["session"];
        assert_eq!(session["id"], ids[i]);
        assert_eq!(session["revealOf"], sid);
        assert_eq!(session["reveal"], i.to_string());
        assert_eq!(session["step"], ["P0", "P0w1", "P0w2"][i]);
        assert_eq!(session["method"], "TEST");
        assert_eq!(p["server_name"], SERVER_DOMAIN);
        assert_eq!(p["config"]["recv"].as_array().unwrap().len(), sets[i].1.len());
        let redacted = p["transcript"]["recv"].as_str().unwrap().as_bytes();
        for &(a, b) in &sets[i].1 {
            assert_eq!(&redacted[a..b], &recv[a..b]);
        }
        // Nothing of another proof's ranges.
        let revealed: usize = redacted.iter().filter(|&&b| b != 0).count();
        let own: usize = sets[i].1.iter().map(|&(a, b)| b - a).sum();
        assert_eq!(revealed, own, "proof {i} carries only its own ranges");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_single_proof_session_is_unchanged() {
    let v = verifier(Settings::default()).await;
    let (mut ws, sid, reply) = register(v.addr, false, json!({ "method": "TEST", "step": "A", "revealOf": "forged" })).await;
    assert!(reply.get("multiReveal").is_none(), "{reply}");
    let (mut prover, handle) = committed_prover(v.addr, &sid).await;
    let reply = prove(&mut ws, &mut prover, &[(0, 14)], &[(0, 15)], true, None).await;
    assert_eq!(reply["type"], "session_completed", "{reply}");
    assert_eq!(text(&reply["results"]).len(), 2);
    prover.close().await.unwrap();
    handle.close();
    // The server closes the socket after the one result.
    assert_eq!(next_text(&mut ws, WAIT).await, None);
    assert!(freed(&v).await);
    let got = payloads(&v, 1).await;
    assert_eq!(got.len(), 1);
    let session = got[0]["session"].as_object().unwrap();
    assert_eq!(session["id"], sid.as_str());
    assert_eq!(session["step"], "A");
    assert!(!session.contains_key("revealOf") && !session.contains_key("reveal"), "{session:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_proof_over_the_ceiling_ends_the_session_and_earlier_results_stand() {
    let v = verifier(Settings {
        max_reveal_blocks: 10,
        ..Settings::default()
    })
    .await;
    let (mut ws, sid, _) = register(v.addr, true, json!({ "method": "TEST", "step": "P0" })).await;
    let (mut prover, _handle) = committed_prover(v.addr, &sid).await;
    let first = prove(&mut ws, &mut prover, &[(0, 14)], &[(0, 15)], true, None).await;
    assert_eq!(first["type"], "reveal_completed", "{first}");
    // 11 blocks: refused at reveal_config, before the prover proves it.
    let over = json!({ "type": "reveal_config", "step": "P0w1", "sent": [],
        "recv": [range(16, 176, "BODY"), range(400, 401, "BODY")] });
    ws.send(Message::Text(over.to_string().into())).await.unwrap();
    let reply = next_text(&mut ws, WAIT).await.expect("an error");
    assert!(reply.contains("\"type\":\"error\"") && reply.contains(REVEAL_TOO_LARGE), "{reply}");
    assert!(freed(&v).await, "the refused session still holds its slot");
    let got = payloads(&v, 1).await;
    assert_eq!(got.len(), 1, "the first proof's result stands");
    assert_eq!(got[0]["session"]["step"], "P0");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_proof_must_name_its_step_and_finish_needs_a_proof() {
    let v = verifier(Settings::default()).await;
    // finish before any proof: not a reveal_config.
    let (mut ws, _sid, _) = register(v.addr, true, json!({ "method": "TEST", "step": "P0" })).await;
    ws.send(Message::Text(json!({ "type": "finish" }).to_string().into())).await.unwrap();
    let reply = next_text(&mut ws, WAIT).await.expect("an error");
    assert!(reply.contains("Expected 'reveal_config'"), "{reply}");

    let (mut ws, sid, _) = register(v.addr, true, json!({ "method": "TEST", "step": "P0" })).await;
    let (mut prover, _handle) = committed_prover(v.addr, &sid).await;
    let first = prove(&mut ws, &mut prover, &[(0, 14)], &[(0, 15)], true, None).await;
    assert_eq!(first["type"], "reveal_completed", "{first}");
    let unnamed = json!({ "type": "reveal_config", "sent": [], "recv": [range(16, 20, "BODY")] });
    ws.send(Message::Text(unnamed.to_string().into())).await.unwrap();
    let reply = next_text(&mut ws, WAIT).await.expect("an error");
    assert!(reply.contains("must name its step"), "{reply}");
    let bad = json!({ "type": "reveal_config", "step": "P0/../x", "sent": [], "recv": [range(16, 20, "BODY")] });
    let (mut ws2, sid2, _) = register(v.addr, true, json!({ "method": "TEST", "step": "P1" })).await;
    let (mut prover2, _handle2) = committed_prover(v.addr, &sid2).await;
    prove(&mut ws2, &mut prover2, &[(0, 14)], &[(0, 15)], true, None).await;
    ws2.send(Message::Text(bad.to_string().into())).await.unwrap();
    let reply = next_text(&mut ws2, WAIT).await.expect("an error");
    assert!(reply.contains("invalid reveal_config step"), "{reply}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_closes_after_a_proof_ends_the_session_cleanly() {
    let v = verifier(Settings {
        memory_budget: Some(MemoryBudget::new(2_600, Duration::from_secs(10))),
        ..Settings::default()
    })
    .await;
    let (mut ws, sid, _) = register(v.addr, true, json!({ "method": "TEST", "step": "P0" })).await;
    let (mut prover, handle) = committed_prover(v.addr, &sid).await;
    let first = prove(&mut ws, &mut prover, &[(0, 14)], &[(0, 15)], true, None).await;
    assert_eq!(first["type"], "reveal_completed");
    drop(ws);
    prover.close().await.unwrap();
    handle.close();
    assert!(freed(&v).await, "slot or memory kept after the client left");
    assert_eq!(payloads(&v, 1).await.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_reservation_follows_the_largest_proof_until_the_session_ends() {
    let v = verifier(Settings {
        memory_budget: Some(MemoryBudget::new(2_600, Duration::from_secs(10))),
        ..Settings::default()
    })
    .await;
    let reserved = || v.state.settings.memory_budget.as_ref().unwrap().reserved_mb();
    let (mut ws, sid, _) = register(v.addr, true, json!({ "method": "TEST", "step": "P0" })).await;
    assert_eq!(reserved(), crate::admission::BASE_MB);
    let (mut prover, handle) = committed_prover(v.addr, &sid).await;
    let head = prover.transcript().received().windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    prove(&mut ws, &mut prover, &[(0, 14)], &[(0, 15)], true, None).await;
    assert_eq!(reserved(), 180);
    // 200 blocks: the next bracket (320 MB).
    let big = prove(&mut ws, &mut prover, &[], &[(head, head + 200 * 16)], false, Some("P0w1")).await;
    assert_eq!(big["type"], "reveal_completed", "{big}");
    assert_eq!(reserved(), 320);
    // A small proof after it does not shrink the reservation.
    prove(&mut ws, &mut prover, &[], &[(head + 4000, head + 4004)], false, Some("P0w2")).await;
    assert_eq!(reserved(), 320);
    ws.send(Message::Text(json!({ "type": "finish" }).to_string().into())).await.unwrap();
    prover.close().await.unwrap();
    handle.close();
    assert!(freed(&v).await, "the reservation outlived the session");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_later_prove_request_over_the_ceiling_is_rejected_at_the_request() {
    let v = verifier(Settings {
        max_reveal_blocks: 10,
        ..Settings::default()
    })
    .await;
    let (mut ws, sid, _) = register(v.addr, true, json!({ "method": "TEST", "step": "P0" })).await;
    let (mut prover, _handle) = committed_prover(v.addr, &sid).await;
    prove(&mut ws, &mut prover, &[(0, 14)], &[(0, 15)], true, None).await;
    // The reveal_config announces 1 block; the prove request carries 11.
    let small = json!({ "type": "reveal_config", "step": "P0w1", "sent": [], "recv": [range(16, 20, "BODY")] });
    ws.send(Message::Text(small.to_string().into())).await.unwrap();
    let mut builder = ProveConfig::builder(prover.transcript());
    builder.reveal_recv(&(16..176)).unwrap();
    builder.reveal_recv(&(400..401)).unwrap();
    let proved = tokio::time::timeout(WAIT, prover.prove(&builder.build().unwrap())).await.expect("prove stalled");
    assert!(proved.is_err(), "the verifier proved an oversize request");
    let reply = next_text(&mut ws, WAIT).await.expect("an error");
    assert!(reply.contains("\"type\":\"error\"") && reply.contains(REVEAL_TOO_LARGE), "{reply}");
    assert!(freed(&v).await);
    assert_eq!(payloads(&v, 1).await.len(), 1);
}

//! Tests for memory-weighted session admission (`TLSN_MEMORY_BUDGET_MB`):
//! the step table, the budget / ceiling settings, the reservation accounting
//! (fit, no fit, monotonic top-up, FIFO queue, timeout, release on drop and on
//! abort) and, over HTTP, the 429 at registration and the refusals at
//! `reveal_config` with their memory released. Local servers only.

use std::sync::Arc;
use std::time::Duration;

use futures_util::SinkExt;
use tokio_tungstenite::tungstenite::Message;

use super::reveal_test::{next_text, registered, reveal_config, serve};
use crate::admission::{
    budget_from_limit, max_affordable_blocks, reserve_mb, MemoryBudget, Refusal, SessionMemory, BASE_MB,
    VERIFIER_BUSY,
};
use crate::reveal::REVEAL_TOO_LARGE;
use crate::settings::{effective_ceiling, resolve_memory_budget, starvation_warning, Settings};

const LONG: Duration = Duration::from_secs(10);
const SHORT: Duration = Duration::from_millis(100);

fn session(budget: &Arc<MemoryBudget>) -> SessionMemory {
    budget.try_session().expect("base reservation fits")
}

// ---------------------------------------------------------------------------
// Table and settings
// ---------------------------------------------------------------------------

#[test]
fn step_table_reserves_the_step_above_each_bracket() {
    assert_eq!(reserve_mb(0), Some(180));
    assert_eq!(reserve_mb(120), Some(180));
    assert_eq!(reserve_mb(121), Some(320));
    assert_eq!(reserve_mb(400), Some(320));
    assert_eq!(reserve_mb(401), Some(520));
    assert_eq!(reserve_mb(820), Some(520));
    assert_eq!(reserve_mb(821), Some(860));
    assert_eq!(reserve_mb(1_402), Some(860));
    assert_eq!(reserve_mb(1_420), Some(860));
    assert_eq!(reserve_mb(1_421), Some(1_640));
    assert_eq!(reserve_mb(1_547), Some(1_640));
    assert_eq!(reserve_mb(2_520), Some(1_640));
    assert_eq!(reserve_mb(2_521), None);
}

#[test]
fn affordable_blocks_follow_the_budget() {
    assert_eq!(max_affordable_blocks(2_600), 2_520);
    assert_eq!(max_affordable_blocks(1_640), 2_520);
    assert_eq!(max_affordable_blocks(1_639), 1_420);
    // 85% of a 1 GB container
    assert_eq!(max_affordable_blocks(870), 1_420);
    assert_eq!(max_affordable_blocks(859), 820);
    assert_eq!(max_affordable_blocks(179), 0);
}

#[test]
fn budget_defaults_to_85_percent_of_the_container_limit() {
    assert_eq!(budget_from_limit(Some(3 * 1024 * 1024 * 1024)), Some(2_611));
    assert_eq!(budget_from_limit(Some(1024 * 1024 * 1024)), Some(870));
    assert_eq!(budget_from_limit(None), None);
    assert_eq!(budget_from_limit(Some(0)), None);
    // cgroup v1 "unlimited"
    assert_eq!(budget_from_limit(Some(9_223_372_036_854_771_712)), None);
    // The variable wins over the container limit.
    assert_eq!(resolve_memory_budget(Some(2_600), Some(1 << 30)), Some(2_600));
    assert_eq!(resolve_memory_budget(None, Some(3 << 30)), Some(2_611));
    assert_eq!(resolve_memory_budget(None, None), None);
}

#[test]
#[should_panic(expected = "below the smallest session reservation")]
fn a_budget_that_admits_nothing_stops_the_server() {
    resolve_memory_budget(Some(100), None);
}

#[test]
fn the_ceiling_is_lowered_to_what_the_budget_affords() {
    assert_eq!(effective_ceiling(2_500, Some(2_600)), 2_500);
    assert_eq!(effective_ceiling(1_400, Some(2_600)), 1_400);
    assert_eq!(effective_ceiling(2_500, Some(870)), 1_420);
    // Past the step table nothing is admissible, whatever the budget.
    assert_eq!(effective_ceiling(4_000, Some(10_000)), 2_520);
    // No budget: as configured.
    assert_eq!(effective_ceiling(4_000, None), 4_000);
    assert!(Settings::default().memory_budget.is_none());
}

#[test]
fn a_sized_deployment_has_no_queue_starvation() {
    // Budget 2600, ceiling 2500, 16 sessions: 15 x 64 + 1640 = 2600.
    assert_eq!(starvation_warning(2_600, 16, 2_500), None);
    let warning = starvation_warning(2_600, 17, 2_500).expect("one session too many");
    assert!(warning.contains("lower TLSN_MAX_SESSIONS to 16"), "{warning}");
}

// ---------------------------------------------------------------------------
// Reservation accounting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn reservations_fit_until_the_budget_is_full() {
    let budget = MemoryBudget::new(1_000, SHORT);
    let a = session(&budget);
    assert_eq!(budget.reserved_mb(), BASE_MB);
    assert_eq!(a.reserve(25).await.unwrap().reserved_mb, 180);
    let b = session(&budget);
    assert_eq!(b.reserve(800).await.unwrap().reserved_mb, 520);
    assert_eq!(budget.reserved_mb(), 700);
    // 700 + 64 + 256 more = 1,020 > 1,000: busy after the wait, nothing kept.
    let c = session(&budget);
    assert_eq!(budget.reserved_mb(), 764);
    match c.reserve(300).await {
        Err(Refusal::Busy { need_mb, waited }) => {
            assert_eq!(need_mb, 320);
            assert!(waited >= SHORT, "{waited:?}");
        }
        other => panic!("expected busy, got {other:?}"),
    }
    assert_eq!(budget.reserved_mb(), 764);
    assert_eq!(c.reserved_mb().await, BASE_MB);
    // Once b is gone, c fits at once.
    drop(b);
    assert_eq!(c.reserve(300).await.unwrap().reserved_mb, 320);
    assert_eq!(budget.reserved_mb(), 500);
    drop((a, c));
    assert_eq!(budget.reserved_mb(), 0);
}

#[tokio::test]
async fn reservation_only_grows_and_a_matching_recheck_is_free() {
    let budget = MemoryBudget::new(2_600, SHORT);
    let s = session(&budget);
    assert_eq!(s.reserve(800).await.unwrap().reserved_mb, 520);
    // The prove request with the same (or fewer) blocks: no change, no wait.
    let again = s.reserve(800).await.unwrap();
    assert_eq!((again.reserved_mb, again.waited), (520, Duration::ZERO));
    assert_eq!(s.reserve(10).await.unwrap().reserved_mb, 520);
    // A larger request tops up to its own bracket.
    assert_eq!(s.reserve(1_547).await.unwrap().reserved_mb, 1_640);
    assert_eq!(budget.reserved_mb(), 1_640);
    drop(s);
    assert_eq!(budget.reserved_mb(), 0);
}

#[tokio::test]
async fn racing_calls_of_one_session_reserve_once() {
    // reveal_config and the prove request of one session at the same time.
    let budget = MemoryBudget::new(2_600, LONG);
    let s = session(&budget);
    let (x, y) = tokio::join!(s.reserve(1_400), s.reserve(1_400));
    assert_eq!(x.unwrap().reserved_mb, 860);
    assert_eq!(y.unwrap().reserved_mb, 860);
    assert_eq!(budget.reserved_mb(), 860);
}

#[tokio::test]
async fn too_large_is_never_admissible_and_not_busy() {
    let budget = MemoryBudget::new(500, LONG);
    let s = session(&budget);
    assert_eq!(s.reserve(800).await, Err(Refusal::TooLarge));
    assert_eq!(s.reserve(2_521).await, Err(Refusal::TooLarge));
    assert_eq!(budget.reserved_mb(), BASE_MB);
    let msg = Refusal::TooLarge.message(800, 500);
    assert!(msg.starts_with(&format!("{REVEAL_TOO_LARGE}: ")), "{msg}");
    let busy = Refusal::Busy {
        need_mb: 320,
        waited: SHORT,
    }
    .message(300, 500);
    assert!(busy.starts_with(&format!("{VERIFIER_BUSY}: ")), "{busy}");
    // A client's busy check matches "busy" or "capacity" and must not see an
    // oversize code.
    let lower = busy.to_ascii_lowercase();
    assert!(lower.contains("busy") && lower.contains("capacity"), "{busy}");
    assert!(!busy.contains(REVEAL_TOO_LARGE), "{busy}");
}

#[tokio::test]
async fn registration_is_refused_without_waiting_when_the_budget_is_full() {
    let budget = MemoryBudget::new(200, LONG);
    let a = session(&budget);
    assert_eq!(a.reserve(50).await.unwrap().reserved_mb, 180);
    assert!(budget.try_session().is_none());
    drop(a);
    assert!(budget.try_session().is_some());
}

#[tokio::test]
async fn the_queue_is_first_in_first_out() {
    // 1,110 MB: a holds 860; b (800 blocks, 456 more) queues first, then c
    // (100 blocks, 116 more). 122 MB are free, enough for c alone, but c must
    // not overtake b: the head of the queue collects what is free.
    let budget = MemoryBudget::new(1_110, LONG);
    let a = session(&budget);
    a.reserve(1_400).await.unwrap();
    let b = Arc::new(session(&budget));
    let c = Arc::new(session(&budget));
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let tb = {
        let (b, tx) = (b.clone(), tx.clone());
        tokio::spawn(async move {
            b.reserve(800).await.unwrap();
            tx.send('b').unwrap();
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let tc = {
        let (c, tx) = (c.clone(), tx.clone());
        tokio::spawn(async move {
            c.reserve(100).await.unwrap();
            tx.send('c').unwrap();
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(rx.try_recv().is_err(), "nobody may pass while the head waits");
    drop(a);
    tb.await.unwrap();
    tc.await.unwrap();
    assert_eq!(rx.recv().await, Some('b'));
    assert_eq!(rx.recv().await, Some('c'));
    assert_eq!(budget.reserved_mb(), 520 + 180);
    drop((b, c));
    assert_eq!(budget.reserved_mb(), 0);
}

#[tokio::test]
async fn an_aborted_waiter_releases_everything() {
    // The handler aborts the verifier task (and a 300 s timeout drops it) while
    // it may be waiting in the queue.
    let budget = MemoryBudget::new(1_000, LONG);
    let a = session(&budget);
    a.reserve(1_400).await.unwrap();
    let waiter = session(&budget);
    let task = tokio::spawn(async move {
        let _ = waiter.reserve(800).await;
        drop(waiter);
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    // The waiter holds at least its base while queued (tokio also sets aside
    // for the queue head what is free).
    assert!(budget.reserved_mb() >= 860 + BASE_MB);
    task.abort();
    let _ = task.await;
    assert_eq!(budget.reserved_mb(), 860);
    drop(a);
    assert_eq!(budget.reserved_mb(), 0);
}

#[tokio::test]
async fn a_timed_out_waiter_hands_back_what_it_collected() {
    let budget = MemoryBudget::new(1_000, SHORT);
    let a = session(&budget);
    a.reserve(1_400).await.unwrap();
    let b = session(&budget);
    assert!(matches!(b.reserve(800).await, Err(Refusal::Busy { .. })));
    assert_eq!(budget.reserved_mb(), 860 + BASE_MB);
    // A newcomer can register again: nothing is stuck with the timed-out waiter.
    drop(b);
    assert!(budget.try_session().is_some());
}

// ---------------------------------------------------------------------------
// Over HTTP: /session
// ---------------------------------------------------------------------------

fn budget_settings(total_mb: u32, wait: Duration) -> Settings {
    Settings {
        memory_budget: Some(MemoryBudget::new(total_mb, wait)),
        ..Settings::default()
    }
}

async fn released(state: &crate::AppState, reserved_mb: u32) -> bool {
    for _ in 0..50 {
        let budget = state.settings.memory_budget.as_ref().unwrap();
        if budget.reserved_mb() == reserved_mb {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn upgrade_gets_429_when_the_memory_budget_is_full() {
    // Room for one base reservation only.
    let (addr, state) = serve(budget_settings(180, LONG)).await;
    let first = registered(addr).await;
    assert_eq!(state.settings.memory_budget.as_ref().unwrap().reserved_mb(), BASE_MB);
    // A second base fits (128 MB); a third would need 192.
    let second = registered(addr).await;
    match tokio_tungstenite::connect_async(format!("ws://{addr}/session")).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 429),
        other => panic!("expected 429, got {:?}", other.map(|_| ())),
    }
    drop((first, second));
}

#[tokio::test]
async fn reveal_config_admitted_reserves_its_step() {
    let (addr, state) = serve(budget_settings(2_600, LONG)).await;
    let mut ws = registered(addr).await;
    // 300 blocks: the 400-block bracket, 320 MB.
    ws.send(Message::Text(reveal_config(&[(0, 300 * 16)]).into()))
        .await
        .unwrap();
    // Forwarded: the session waits for its prover and says nothing yet.
    assert_eq!(next_text(&mut ws, Duration::from_millis(800)).await, None);
    assert_eq!(state.settings.memory_budget.as_ref().unwrap().reserved_mb(), 320);
}

#[tokio::test]
async fn reveal_config_without_room_is_busy_and_frees_the_session() {
    let (addr, state) = serve(Settings {
        max_sessions: 2,
        ..budget_settings(500, Duration::from_millis(300))
    })
    .await;
    // a: 300 blocks, 320 MB.
    let mut a = registered(addr).await;
    a.send(Message::Text(reveal_config(&[(0, 300 * 16)]).into()))
        .await
        .unwrap();
    assert_eq!(next_text(&mut a, Duration::from_millis(500)).await, None);
    // b: 320 + 64 held, needs 256 more of the 116 left: busy after 300 ms.
    let mut b = registered(addr).await;
    b.send(Message::Text(reveal_config(&[(0, 300 * 16)]).into()))
        .await
        .unwrap();
    let reply = next_text(&mut b, Duration::from_secs(5)).await.expect("an error reply");
    assert!(reply.contains("\"type\":\"error\""), "{reply}");
    assert!(reply.contains(VERIFIER_BUSY), "{reply}");
    // b's base, its session and its slot are released; a keeps its 320.
    assert!(released(&state, 320).await, "b still holds memory");
    let mut freed = false;
    for _ in 0..50 {
        if state.sessions.lock().await.len() == 1 && state.settings.active_sessions() == 1 {
            freed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(freed, "the refused session still holds its slot");
    // The freed slot and memory take a new session.
    let _c = registered(addr).await;
}

#[tokio::test]
async fn reveal_config_over_the_whole_budget_is_too_large() {
    // No ceiling configured (Settings::default), so the budget refuses it.
    let (addr, state) = serve(budget_settings(500, LONG)).await;
    let mut ws = registered(addr).await;
    ws.send(Message::Text(reveal_config(&[(0, 800 * 16)]).into()))
        .await
        .unwrap();
    let reply = next_text(&mut ws, Duration::from_secs(5)).await.expect("an error reply");
    assert!(reply.contains(REVEAL_TOO_LARGE), "{reply}");
    assert!(released(&state, 0).await, "the refused session still holds memory");
}

#[tokio::test]
async fn a_socket_closed_before_registering_releases_its_base() {
    let (addr, state) = serve(budget_settings(2_600, LONG)).await;
    let (ws, _) = tokio_tungstenite::connect_async(format!("ws://{addr}/session"))
        .await
        .expect("upgrade");
    assert!(released(&state, BASE_MB).await);
    drop(ws);
    assert!(released(&state, 0).await, "a closed socket still holds memory");
}

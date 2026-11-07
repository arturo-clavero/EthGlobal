//! Memory-weighted session admission (`TLSN_MEMORY_BUDGET_MB`).
//!
//! A session count cannot bound verifier memory: a 25-block proof peaks
//! at about 80 MB, a 1,400-block proof at about 510 MB (and one allocation step
//! higher, about 860 MB, under concurrency). So every session reserves megabytes
//! from one budget, in two phases:
//!
//! 1. at the `/session` upgrade, `BASE_MB` (a session that has preprocessed and
//!    finished its TLS transfer holds about 55-60 MB until it proves). No budget
//!    left: 429, like the session-count caps;
//! 2. at `reveal_config` (the blocks are known), the rest of its step budget
//!    (`reserve_mb`), waiting up to `QUEUE_WAIT` in one FIFO queue (a fair tokio
//!    semaphore) for sessions ahead of it to finish. Still no room: the session
//!    fails with `VERIFIER_BUSY` (a client backs off and retries, as on 429).
//!
//! The verifier task repeats step 2 with the prover's prove request before
//! `accept()` (authoritative: `reveal_config` is what the client announces; the
//! prove phase is where memory grows). The reservation only grows, so the second
//! call is free when the request matches the `reveal_config`, and it waits for the
//! first when both race. Everything is released when the session's slot drops
//! (socket handler and verifier task both done), on every exit path.
//!
//! The step table is measured (verifier-only peaks per block count). Memory
//! grows in steps (allocations that double) and, with sessions running
//! concurrently, a session can land one step higher than it does alone (3 x 800
//! blocks: one at ~520 MB instead of ~310; 3 x 1,400: 2.07 GB). Each bracket
//! therefore reserves the next step above the one measured at its upper end.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

/// (largest block count, MB the session reserves in total), first match. The
/// count is the whole reveal (sent + received, as `reveal.rs` counts it); each
/// bound is about 20 blocks over the measured point for the sent side (request
/// line and headers; the bench proves 2 sent blocks). Verifier-only peaks
/// measured alone near the upper end of each bracket: 102 blocks 113 MB, 321
/// ~173 and 452 ~215, 802 ~319, 1,402 ~510, 2,502 ~883; the next steps up are
/// about 175, 300-320, 465-520, 850-860 and 1,620-1,640 MB. Past the last row
/// nothing is admissible (the ceiling stops it first).
pub(crate) const STEPS: &[(usize, u32)] = &[
    (120, 180),
    (400, 320),
    (820, 520),
    (1_420, 860),
    (2_520, 1_640),
];

/// Reserved from the `/session` upgrade until the blocks are known: an idle
/// session that has preprocessed holds 55-61 MB.
pub(crate) const BASE_MB: u32 = 64;

/// Longest wait in the admission queue at `reveal_config` and at the prove
/// request. Far inside the 180 s `reveal_config` and 300 s verification
/// timeouts; a proof waits at most this long before `VERIFIER_BUSY`.
pub(crate) const QUEUE_WAIT: Duration = Duration::from_secs(30);

/// `TLSN_MEMORY_BUDGET_MB` when unset: this share of the container's memory
/// limit; the rest covers the process base and allocator slack (a one-shot
/// process keeps 73-84 MB after a session).
pub(crate) const DEFAULT_BUDGET_PERCENT: u64 = 85;

/// Error code of a session that did not get its memory in time. Retryable: the
/// message says "busy" and "capacity", as a 429 does.
pub(crate) const VERIFIER_BUSY: &str = "VERIFIER_BUSY";

/// The session's total reservation for a reveal of `blocks` AES blocks, or
/// `None` past the table.
pub(crate) fn reserve_mb(blocks: usize) -> Option<u32> {
    STEPS.iter().find(|(max, _)| blocks <= *max).map(|&(_, mb)| mb)
}

/// The largest block count one session can be admitted with inside `budget_mb`
/// on its own (0: not even the smallest bracket fits).
pub(crate) fn max_affordable_blocks(budget_mb: u32) -> usize {
    STEPS
        .iter()
        .filter(|(_, mb)| *mb <= budget_mb)
        .map(|&(max, _)| max)
        .max()
        .unwrap_or(0)
}

/// `TLSN_MEMORY_BUDGET_MB` default from a cgroup memory limit in bytes: 85% of
/// it, in MB. `None` without a limit (unset, `max`, or the v1 "unlimited"
/// sentinel near `i64::MAX`).
pub(crate) fn budget_from_limit(limit_bytes: Option<u64>) -> Option<u32> {
    let limit = limit_bytes.filter(|&b| b > 0 && b < 1 << 60)?;
    let mb = limit / (1024 * 1024) * DEFAULT_BUDGET_PERCENT / 100;
    u32::try_from(mb).ok().filter(|&mb| mb > 0)
}

/// The container's memory limit (cgroup v2 `memory.max`, else v1
/// `memory.limit_in_bytes`), `None` when there is none or it is unreadable.
pub(crate) fn cgroup_limit_bytes() -> Option<u64> {
    ["/sys/fs/cgroup/memory.max", "/sys/fs/cgroup/memory/memory.limit_in_bytes"]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .and_then(|v| v.trim().parse::<u64>().ok())
}

/// One verifier's memory budget, in MB: a fair (FIFO) weighted semaphore.
pub(crate) struct MemoryBudget {
    sem: Arc<Semaphore>,
    total_mb: u32,
    wait: Duration,
}

impl MemoryBudget {
    pub(crate) fn new(total_mb: u32, wait: Duration) -> Arc<Self> {
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(total_mb as usize)),
            total_mb,
            wait,
        })
    }

    pub(crate) fn total_mb(&self) -> u32 {
        self.total_mb
    }

    /// MB held by sessions (including what is already set aside for the head of
    /// the queue).
    pub(crate) fn reserved_mb(&self) -> u32 {
        self.total_mb - self.sem.available_permits() as u32
    }

    /// Phase 1: the base reservation of a new session, without waiting. `None`
    /// when the budget is full (or the queue head is collecting what is freed).
    pub(crate) fn try_session(self: &Arc<Self>) -> Option<SessionMemory> {
        let base = BASE_MB.min(self.total_mb);
        let permit = self.sem.clone().try_acquire_many_owned(base).ok()?;
        Some(SessionMemory {
            budget: self.clone(),
            held: Mutex::new(permit),
        })
    }
}

/// What one session holds; released when dropped.
pub(crate) struct SessionMemory {
    budget: Arc<MemoryBudget>,
    held: Mutex<OwnedSemaphorePermit>,
}

/// A granted reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Admitted {
    /// The session's total reservation now.
    pub(crate) reserved_mb: u32,
    /// Time spent in the queue (zero when it fitted at once or already held it).
    pub(crate) waited: Duration,
}

/// Why a reservation was not granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The budget had no room within the wait. Retryable.
    Busy { need_mb: u32, waited: Duration },
    /// The reveal needs more than the whole budget (or is past the step table):
    /// never admissible. The ceiling (clamped to `max_affordable_blocks`) refuses
    /// such a reveal before it gets here.
    TooLarge,
}

impl Refusal {
    /// The session's error text. Busy starts with `VERIFIER_BUSY`; too large with
    /// `REVEAL_TOO_LARGE`, so a client skips it instead of retrying.
    pub(crate) fn message(&self, blocks: usize, budget_mb: u32) -> String {
        match self {
            Refusal::Busy { .. } => format!(
                "{VERIFIER_BUSY}: the verifier is busy (memory at capacity), retry shortly"
            ),
            Refusal::TooLarge => format!(
                "{}: the reveal touches {blocks} AES blocks, over the verifier memory budget of {budget_mb} MB",
                crate::reveal::REVEAL_TOO_LARGE
            ),
        }
    }
}

impl SessionMemory {
    /// The session's total reservation.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn reserved_mb(&self) -> u32 {
        self.held.lock().await.num_permits() as u32
    }

    /// Phase 2: hold at least the step budget of `blocks`, waiting in the FIFO
    /// queue up to the budget's wait for the missing part. Monotonic: a session
    /// that already holds enough returns at once. Concurrent calls of one session
    /// run one after the other.
    pub(crate) async fn reserve(&self, blocks: usize) -> Result<Admitted, Refusal> {
        let budget = &self.budget;
        let need = match reserve_mb(blocks) {
            Some(mb) if mb <= budget.total_mb => mb,
            _ => return Err(Refusal::TooLarge),
        };
        let mut held = self.held.lock().await;
        let have = held.num_permits() as u32;
        if have >= need {
            return Ok(Admitted {
                reserved_mb: have,
                waited: Duration::ZERO,
            });
        }
        let start = Instant::now();
        // Dropping the acquire future (timeout, aborted task) leaves the queue and
        // returns whatever had been set aside for it.
        match tokio::time::timeout(budget.wait, budget.sem.clone().acquire_many_owned(need - have)).await {
            Ok(Ok(more)) => {
                held.merge(more);
                Ok(Admitted {
                    reserved_mb: need,
                    waited: start.elapsed(),
                })
            }
            // Never closed; treated as busy if it were.
            Ok(Err(_)) | Err(_) => Err(Refusal::Busy {
                need_mb: need,
                waited: start.elapsed(),
            }),
        }
    }
}

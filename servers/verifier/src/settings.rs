//! Runtime settings, read from the environment once at start-up.
//! `Default` keeps upstream behaviour (no limits), so tests can build a server
//! with only what they exercise; `from_env` is what the binary uses.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// `TLSN_MAX_SESSIONS` when unset.
pub(crate) const DEFAULT_MAX_SESSIONS: usize = 20;
/// How long a new /session socket may take to send `register`.
pub(crate) const REGISTER_TIMEOUT: Duration = Duration::from_secs(30);
/// How long after `register` the client may take to send `reveal_config`
/// (covers the 30 s prover connect plus the TLS connection).
pub(crate) const REVEAL_CONFIG_TIMEOUT: Duration = Duration::from_secs(180);
/// How long a multi-reveal session may wait after a proof's result for its
/// next `reveal_config` (or `finish`). Past it the session ends as if
/// finished; the results already delivered stand.
pub(crate) const NEXT_REVEAL_TIMEOUT: Duration = Duration::from_secs(60);
/// Proofs one multi-reveal session may make.
pub(crate) const MAX_REVEALS_PER_SESSION: usize = 64;

#[derive(Clone)]
pub(crate) struct Settings {
    /// New `/session` upgrades get 429 when this many sessions are active.
    pub(crate) max_sessions: usize,
    pub(crate) active_sessions: Arc<AtomicUsize>,
    /// Optional ceilings on the client-declared maxRecvData / maxSentData.
    /// `None` keeps upstream behaviour (any value).
    pub(crate) max_recv_data: Option<usize>,
    pub(crate) max_sent_data: Option<usize>,
    /// A session whose reveal touches more 16-byte AES blocks than this is
    /// refused with `REVEAL_TOO_LARGE` (`TLSN_MAX_REVEAL_BLOCKS`, `reveal.rs`).
    /// `Default` = unlimited (upstream behaviour, tests); `from_env` defaults to
    /// `reveal::DEFAULT_MAX_REVEAL_BLOCKS`.
    pub(crate) max_reveal_blocks: usize,
    /// Memory-weighted admission (`TLSN_MEMORY_BUDGET_MB`, `admission.rs`).
    /// `None` = no memory budget (upstream behaviour, tests; `from_env` when the
    /// variable is unset and the container has no memory limit).
    pub(crate) memory_budget: Option<Arc<crate::admission::MemoryBudget>>,
    /// Tests only: the address a Proxy-mode session dials instead of
    /// `<host>:443` (a local TLS fixture).
    #[cfg(test)]
    pub(crate) test_dial: Option<String>,
    /// Tests only: DER root certificates replacing Mozilla's (the fixture's CA).
    #[cfg(test)]
    pub(crate) test_roots: Option<Vec<Vec<u8>>>,
}

/// Holds one active-session slot; released on drop. Shared by the session
/// socket handler and its verifier task, so it is freed when both are done.
pub(crate) struct SessionSlot {
    active: Arc<AtomicUsize>,
    /// The session's memory reservation, when the verifier has a budget (set
    /// by the `/session` handler after the count).
    pub(crate) memory: Option<crate::admission::SessionMemory>,
}

impl Drop for SessionSlot {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            max_sessions: usize::MAX,
            active_sessions: Arc::new(AtomicUsize::new(0)),
            max_recv_data: None,
            max_sent_data: None,
            max_reveal_blocks: usize::MAX,
            memory_budget: None,
            #[cfg(test)]
            test_dial: None,
            #[cfg(test)]
            test_roots: None,
        }
    }
}

impl Settings {
    pub(crate) fn from_env() -> Self {
        // The memory budget, and the ceiling clamped to what one session can be
        // admitted with inside it.
        let max_sessions = env_usize("TLSN_MAX_SESSIONS").unwrap_or(DEFAULT_MAX_SESSIONS);
        let budget_mb = resolve_memory_budget(
            env_usize("TLSN_MEMORY_BUDGET_MB"),
            crate::admission::cgroup_limit_bytes(),
        );
        let configured_ceiling = env_usize("TLSN_MAX_REVEAL_BLOCKS")
            .unwrap_or(crate::reveal::DEFAULT_MAX_REVEAL_BLOCKS);
        let max_reveal_blocks = effective_ceiling(configured_ceiling, budget_mb);
        match budget_mb {
            None => tracing::warn!(
                "TLSN_MEMORY_BUDGET_MB unset and no container memory limit: no memory-weighted admission"
            ),
            Some(mb) => {
                tracing::info!(
                    "Memory budget {mb} MB; reveal ceiling {max_reveal_blocks} AES blocks (configured {configured_ceiling})"
                );
                if max_reveal_blocks < configured_ceiling {
                    tracing::warn!(
                        "TLSN_MAX_REVEAL_BLOCKS {configured_ceiling} lowered to {max_reveal_blocks}: one session over it needs more than the {mb} MB budget"
                    );
                }
                if let Some(warning) = starvation_warning(mb, max_sessions, max_reveal_blocks) {
                    tracing::warn!("{warning}");
                }
            }
        }
        Self {
            max_sessions,
            max_recv_data: env_usize("TLSN_MAX_RECV_DATA"),
            max_sent_data: env_usize("TLSN_MAX_SENT_DATA"),
            max_reveal_blocks,
            memory_budget: budget_mb
                .map(|mb| crate::admission::MemoryBudget::new(mb, crate::admission::QUEUE_WAIT)),
            ..Self::default()
        }
    }

    /// Reserve an active-session slot, or `None` when at `max_sessions`.
    pub(crate) fn try_acquire_session(&self) -> Option<SessionSlot> {
        self.active_sessions
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
                (n < self.max_sessions).then_some(n + 1)
            })
            .ok()
            .map(|_| SessionSlot {
                active: self.active_sessions.clone(),
                memory: None,
            })
    }

    pub(crate) fn active_sessions(&self) -> usize {
        self.active_sessions.load(Ordering::SeqCst)
    }
}

/// `TLSN_MEMORY_BUDGET_MB` if set, else 85% of the container limit, else
/// `None` (no budget). Panics at start-up on a budget below the smallest session
/// reservation (nothing could ever be admitted) or over `u32::MAX` MB.
pub(crate) fn resolve_memory_budget(env_mb: Option<usize>, cgroup_bytes: Option<u64>) -> Option<u32> {
    let mb = match env_mb {
        Some(mb) => Some(u32::try_from(mb).unwrap_or_else(|_| {
            panic!("TLSN_MEMORY_BUDGET_MB must be a positive integer of MB, got {mb}")
        })),
        None => crate::admission::budget_from_limit(cgroup_bytes),
    }?;
    let smallest = crate::admission::STEPS[0].1;
    if mb < smallest {
        panic!("TLSN_MEMORY_BUDGET_MB is {mb} MB, below the smallest session reservation ({smallest} MB)");
    }
    Some(mb)
}

/// The reveal ceiling in force: the configured one, lowered with a budget to
/// the largest reveal one session can be admitted with inside it alone.
pub(crate) fn effective_ceiling(configured: usize, budget_mb: Option<u32>) -> usize {
    match budget_mb {
        Some(mb) => configured.min(crate::admission::max_affordable_blocks(mb)),
        None => configured,
    }
}

/// Sessions waiting in the admission queue hold their base reservation. When
/// `max_sessions - 1` such bases plus one session at the ceiling exceed the
/// budget, the queue head can wait out its turn (it then gets VERIFIER_BUSY;
/// nothing deadlocks, but it is wasted work), so say so at start-up.
pub(crate) fn starvation_warning(budget_mb: u32, max_sessions: usize, ceiling: usize) -> Option<String> {
    let top = crate::admission::reserve_mb(ceiling)? as u64;
    let bases = (max_sessions.saturating_sub(1) as u64).saturating_mul(crate::admission::BASE_MB as u64);
    (bases + top > budget_mb as u64).then(|| {
        format!(
            "TLSN_MAX_SESSIONS {max_sessions}: {} waiting sessions hold {bases} MB, which with one {ceiling}-block session ({top} MB) exceeds the {budget_mb} MB budget; lower TLSN_MAX_SESSIONS to {} or raise the budget",
            max_sessions - 1,
            (budget_mb as u64 - top) / crate::admission::BASE_MB as u64 + 1
        )
    })
}

/// Positive integer env value; panics at start-up on a malformed value so a
/// typo cannot silently disable a limit.
fn env_usize(name: &str) -> Option<usize> {
    env_nonempty(name).map(|v| match v.parse::<usize>() {
        Ok(n) if n > 0 => n,
        _ => panic!("{name} must be a positive integer, got {v:?}"),
    })
}

/// Trimmed env value, `None` when unset or blank.
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

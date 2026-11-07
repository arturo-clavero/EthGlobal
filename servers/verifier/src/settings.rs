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
            #[cfg(test)]
            test_dial: None,
            #[cfg(test)]
            test_roots: None,
        }
    }
}

impl Settings {
    pub(crate) fn from_env() -> Self {
        Self {
            max_sessions: env_usize("TLSN_MAX_SESSIONS").unwrap_or(DEFAULT_MAX_SESSIONS),
            max_recv_data: env_usize("TLSN_MAX_RECV_DATA"),
            max_sent_data: env_usize("TLSN_MAX_SENT_DATA"),
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
            })
    }

    pub(crate) fn active_sessions(&self) -> usize {
        self.active_sessions.load(Ordering::SeqCst)
    }
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

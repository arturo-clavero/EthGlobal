//! Revealed-size ceiling (`TLSN_MAX_REVEAL_BLOCKS`).
//!
//! The verifier's memory during the prove phase grows with the number of 16-byte
//! AES-CTR blocks the authenticated ranges touch (one AES circuit per block in
//! `tlsn` `transcript_internal/auth.rs`), not with the response size: measured
//! verifier-only peaks are about 170 MB at
//! 319 blocks, 300 MB at 650-800, 465-510 MB at 1000-1400, 520 or 850 MB at 1500
//! (a step edge) and 1.6 GB at 3000-4000. One large proof could OOM-kill the
//! container and drop every other session, so a session whose reveal touches
//! more than the ceiling is refused before the prove phase:
//!
//! - at `reveal_config` (the extension sends it before `prove()`): the session
//!   gets `REVEAL_TOO_LARGE: …` and its verifier task is stopped;
//! - at the prover's prove request, before `accept()` (authoritative: the request
//!   is what the verifier would prove; a client can send a small `reveal_config`
//!   and prove more): the request is rejected with the same code.
//!
//! The count is `offset / 16` over the union of the ranges per direction (revealed
//! and hash-committed: both are authenticated in ZK). A real response restarts the
//! AES-CTR counter at every TLS record, so the true count can exceed this by at
//! most one block per range that crosses a record boundary (at most one per
//! record: about 32 for a 512 KiB response); the default leaves that margin
//! below the next memory step.

use std::ops::Range;

/// `TLSN_MAX_REVEAL_BLOCKS` when unset: the last bracket of the memory admission
/// table (2,500 blocks: ~883 MB alone, 1,640 MB reserved). With a memory budget
/// the ceiling in force is lowered to what one session can be admitted with
/// (`settings::effective_ceiling`; 1,420 for a budget under 1,640 MB).
pub(crate) const DEFAULT_MAX_REVEAL_BLOCKS: usize = 2_500;

/// Error code of a refused reveal. The extension surfaces the message text; a
/// client should treat it as oversize (do not retry the same proof), never as
/// busy.
pub(crate) const REVEAL_TOO_LARGE: &str = "REVEAL_TOO_LARGE";

const AES_BLOCK: usize = 16;

/// Distinct 16-byte blocks (by transcript offset) that the ranges touch. Empty and
/// inverted ranges count nothing; overlapping ranges count once.
pub(crate) fn aes_blocks<I: IntoIterator<Item = Range<usize>>>(ranges: I) -> usize {
    let mut spans: Vec<(usize, usize)> = ranges
        .into_iter()
        .filter(|r| r.start < r.end)
        .map(|r| (r.start / AES_BLOCK, (r.end - 1) / AES_BLOCK))
        .collect();
    spans.sort_unstable();
    let mut total = 0usize;
    let mut next = 0usize; // first block not counted yet
    for (first, last) in spans {
        let first = first.max(next);
        if first <= last {
            total += last - first + 1;
            next = last + 1;
        }
    }
    total
}

/// Blocks of a `reveal_config` (both directions, every handler action).
pub(crate) fn reveal_config_blocks(sent: &[Range<usize>], recv: &[Range<usize>]) -> usize {
    aes_blocks(sent.iter().cloned()) + aes_blocks(recv.iter().cloned())
}

/// Blocks of the prover's prove request: revealed ranges plus hash commitments,
/// per direction.
pub(crate) fn request_blocks(request: &tlsn::config::prove::ProveRequest) -> usize {
    use tlsn::transcript::Direction;
    let mut sent: Vec<Range<usize>> = Vec::new();
    let mut recv: Vec<Range<usize>> = Vec::new();
    if let Some((s, r)) = request.reveal() {
        sent.extend(s.iter());
        recv.extend(r.iter());
    }
    if let Some(commit) = request.transcript_commit() {
        for (direction, idx, _) in commit.iter_hash() {
            match direction {
                Direction::Sent => sent.extend(idx.iter()),
                Direction::Received => recv.extend(idx.iter()),
            }
        }
    }
    aes_blocks(sent) + aes_blocks(recv)
}

/// `Some(message)` when `blocks` is over `limit`. The message starts with the code.
pub(crate) fn check(blocks: usize, limit: usize) -> Option<String> {
    (blocks > limit).then(|| {
        format!("{REVEAL_TOO_LARGE}: the reveal touches {blocks} AES blocks, over the verifier limit of {limit}")
    })
}

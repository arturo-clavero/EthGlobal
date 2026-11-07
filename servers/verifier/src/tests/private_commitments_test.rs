//! Security regressions for hash-only transcript results; no network or prover.

use rangeset::set::RangeSet;
use tlsn::{
    hash::{HashAlgId, TypedHash},
    transcript::{hash::PlaintextHash, Direction, PartialTranscript, Subsequence, TranscriptCommitment},
};

use crate::{
    find_hash_digest, process_ranges, verify_reveal_config, Handler, HandlerAction, HandlerPart,
    HandlerType, HashAlgorithm, RangeWithHandler, RevealConfig,
};

fn commitment(direction: Direction, idx: RangeSet<usize>, alg: HashAlgId) -> TranscriptCommitment {
    TranscriptCommitment::Hash(PlaintextHash {
        direction,
        idx,
        hash: TypedHash {
            alg,
            value: vec![0xab; 32].try_into().unwrap(),
        },
    })
}

fn range(start: usize, end: usize, handler_type: HandlerType) -> RangeWithHandler {
    RangeWithHandler {
        start,
        end,
        handler: Handler {
            handler_type,
            part: HandlerPart::All,
            action: HandlerAction::Hash {
                algorithm: HashAlgorithm::Sha256,
            },
        },
    }
}

#[test]
fn hash_result_requires_exact_indices_direction_and_algorithm() {
    let cases = [
        (Direction::Sent, RangeSet::from(2..6), HashAlgId::SHA256, true),
        (Direction::Received, RangeSet::from(2..6), HashAlgId::SHA256, false),
        (Direction::Sent, RangeSet::from(2..6), HashAlgId::BLAKE3, false),
        (Direction::Sent, RangeSet::from(2..6), HashAlgId::KECCAK256, false),
        (Direction::Sent, RangeSet::from(1..7), HashAlgId::SHA256, false),
        (Direction::Sent, RangeSet::from(3..5), HashAlgId::SHA256, false),
        (Direction::Sent, RangeSet::from([2..4, 5..6]), HashAlgId::SHA256, false),
        (Direction::Sent, RangeSet::from([2..6, 8..9]), HashAlgId::SHA256, false),
    ];
    for (direction, idx, algorithm, accepted) in cases {
        let result = find_hash_digest(
            &[commitment(direction, idx, algorithm)],
            Direction::Sent,
            2,
            6,
            HashAlgorithm::Sha256,
        );
        assert_eq!(result.is_some(), accepted);
        if accepted {
            assert_eq!(result.unwrap(), "ab".repeat(32));
        }
    }
}

#[test]
fn zero_reveal_full_hashes_validate_and_render_only_digests() {
    let transcript = PartialTranscript::new(12, 23);
    let config = RevealConfig {
        step: None,
        sent: vec![range(0, 12, HandlerType::Sent)],
        recv: vec![range(0, 23, HandlerType::Recv)],
    };
    let commitments = [
        commitment(Direction::Sent, RangeSet::from(0..12), HashAlgId::SHA256),
        commitment(Direction::Received, RangeSet::from(0..23), HashAlgId::SHA256),
    ];
    assert!(verify_reveal_config(&config, &transcript, &commitments).is_ok());
    for (ranges, bytes, direction) in [
        (&config.sent, transcript.sent_unsafe(), Direction::Sent),
        (&config.recv, transcript.received_unsafe(), Direction::Received),
    ] {
        assert!(bytes.iter().all(|byte| *byte == 0));
        let results = process_ranges(ranges, bytes, direction, &commitments, "test", "test");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].value, "ab".repeat(32));
    }
    assert!(transcript.sent_authed().is_empty());
    assert!(transcript.received_authed().is_empty());
}

#[test]
fn all_handler_cannot_label_a_partial_commitment_as_full_transcript() {
    let transcript = PartialTranscript::new(12, 23);
    for (start, end) in [(0, 11), (1, 12), (0, 13), (0, 0), (6, 2)] {
        let config = RevealConfig {
            step: None,
            sent: vec![range(start, end, HandlerType::Sent)],
            recv: vec![],
        };
        let commitments = [commitment(
            Direction::Sent,
            RangeSet::from(if start < end { start..end } else { 0..12 }),
            HashAlgId::SHA256,
        )];
        assert!(verify_reveal_config(&config, &transcript, &commitments).is_err());
    }
}

#[test]
fn reveal_and_hash_actions_cannot_substitute_each_others_evidence() {
    let mut transcript = PartialTranscript::new(12, 0);
    let commitments = [commitment(Direction::Sent, RangeSet::from(0..12), HashAlgId::SHA256)];
    let mut config = RevealConfig {
        step: None,
        sent: vec![range(0, 12, HandlerType::Sent)],
        recv: vec![],
    };
    config.sent[0].handler.action = HandlerAction::Reveal;
    assert!(verify_reveal_config(&config, &transcript, &commitments).is_err());
    transcript.union_subsequence(
        Direction::Sent,
        &Subsequence::new(RangeSet::from(0..12), b"secret bytes".to_vec()).unwrap(),
    );
    assert!(verify_reveal_config(&config, &transcript, &[]).is_ok());
    config.sent[0].handler.action = HandlerAction::Hash { algorithm: HashAlgorithm::Blake3 };
    assert!(verify_reveal_config(&config, &transcript, &commitments).is_err());
    config.sent[0].handler.action = HandlerAction::Hash { algorithm: HashAlgorithm::Sha256 };
    config.sent[0].handler.handler_type = HandlerType::Recv;
    assert!(verify_reveal_config(&config, &transcript, &commitments).is_err());
    config.sent[0].handler.handler_type = HandlerType::Sent;
    assert!(verify_reveal_config(&config, &transcript, &[]).is_err());
}

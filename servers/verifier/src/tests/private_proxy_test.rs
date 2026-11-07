//! Hash-only and mixed disclosures through a real Proxy-mode prover and
//! verifier (in process, over an in-memory TLS 1.2 server). The server uses
//! the public test credentials of the pinned core (`tlsn-server-fixture-certs`);
//! production trust roots and network routing are not changed by this test.

use std::{future::IntoFuture, time::Duration};

use sha2::{Digest, Sha256};
use tlsn::{
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::proxy::ProxyTlsConfig, verifier::VerifierConfig,
    },
    connection::{DnsName, ServerName},
    hash::HashAlgId,
    transcript::{Direction, TranscriptCommitConfig, TranscriptCommitment, TranscriptCommitmentKind, TranscriptSecret},
    verifier::VerifierCommitStart,
    webpki::{CertificateDer, RootCertStore},
    Session,
};
use tlsn_server_fixture_certs::{CA_CERT_DER, SERVER_CERT_DER, SERVER_DOMAIN, SERVER_KEY_DER};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

const HOST: &str = "test-server.io";
const REQUEST: &[u8] = b"GET /?project=private-project&principal=private-user HTTP/1.1\r\nHost: test-server.io\r\nAuthorization: Bearer synthetic-secret\r\nConnection: close\r\n\r\n";
const BODY: &str = "{\"entries\":[{\"timestamp\":\"2026-10-13T00:00:00Z\"}]}";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_commitments_proxy_no_reveal() {
    tokio::time::timeout(Duration::from_secs(120), roundtrip(false))
        .await
        .expect("private Proxy roundtrip timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_commitments_proxy_mixed_reveal() {
    tokio::time::timeout(Duration::from_secs(120), roundtrip(true))
        .await
        .expect("mixed Proxy roundtrip timed out");
}

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

// Partition a known fixture section, keeping its private values as individual
// contiguous commitments. Production callers must derive equivalent ranges from
// a validated HTTP/schema policy, not trust these test-only fixture searches.
fn partition(
    bytes: &[u8],
    start: usize,
    end: usize,
    secrets: &[&[u8]],
    handler_type: crate::HandlerType,
    part: crate::HandlerPart,
) -> Vec<crate::RangeWithHandler> {
    let mut ranges = Vec::new();
    let mut cursor = start;
    for secret in secrets {
        let offset = bytes[cursor..end].windows(secret.len())
            .position(|window| window == *secret).expect("fixture secret missing");
        let secret_start = cursor + offset;
        if cursor < secret_start {
            ranges.push((cursor, secret_start, crate::HandlerAction::Reveal));
        }
        cursor = secret_start + secret.len();
        ranges.push((secret_start, cursor, crate::HandlerAction::Hash {
            algorithm: crate::HashAlgorithm::Sha256,
        }));
    }
    if cursor < end {
        ranges.push((cursor, end, crate::HandlerAction::Reveal));
    }
    ranges.into_iter().map(|(start, end, action)| crate::RangeWithHandler {
        start, end,
        handler: crate::Handler { handler_type: handler_type.clone(), part: part.clone(), action },
    }).collect()
}

fn disclosure_config(mixed: bool, response: &[u8]) -> crate::RevealConfig {
    use crate::{HandlerAction, HandlerPart, HandlerType};

    if !mixed {
        let all = |length, handler_type| crate::RangeWithHandler {
            start: 0, end: length,
            handler: crate::Handler {
                handler_type, part: HandlerPart::All,
                action: HandlerAction::Hash { algorithm: crate::HashAlgorithm::Sha256 },
            },
        };
        return crate::RevealConfig {
            sent: vec![all(REQUEST.len(), HandlerType::Sent)],
            recv: vec![all(response.len(), HandlerType::Recv)],
        };
    }
    let sent_line_end = REQUEST.windows(2).position(|bytes| bytes == b"\r\n").unwrap() + 2;
    let mut sent = partition(REQUEST, 0, sent_line_end,
        &[b"private-project", b"private-user"], HandlerType::Sent, HandlerPart::StartLine);
    sent.extend(partition(REQUEST, sent_line_end, REQUEST.len(),
        &[b"synthetic-secret"], HandlerType::Sent, HandlerPart::Headers));
    let recv_line_end = response.windows(2).position(|bytes| bytes == b"\r\n").unwrap() + 2;
    let body_start = response.len() - BODY.len();
    let mut recv = partition(response, 0, recv_line_end, &[], HandlerType::Recv, HandlerPart::StartLine);
    recv.extend(partition(response, recv_line_end, body_start, &[], HandlerType::Recv, HandlerPart::Headers));
    recv.extend(partition(response, body_start, response.len(),
        &[b"\"2026-10-13T00:00:00Z\""], HandlerType::Recv, HandlerPart::Body));
    crate::RevealConfig { sent, recv }
}

async fn roundtrip(mixed: bool) {
    assert_eq!(SERVER_DOMAIN, HOST);
    let ca = CA_CERT_DER.to_vec();
    let identity = native_tls::Identity::from_pkcs8(
        &pem("CERTIFICATE", SERVER_CERT_DER),
        &pem("PRIVATE KEY", SERVER_KEY_DER),
    ).unwrap();
    let roots = || RootCertStore { roots: vec![CertificateDer(ca.clone())] };
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        BODY.len(), BODY,
    ).into_bytes();
    let expected_response = response.clone();
    let disclosure = disclosure_config(mixed, &response);
    let expected_commitments = if mixed { 4 } else { 2 };

    let (upstream_socket, server_socket) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(async move {
        let mut builder = native_tls::TlsAcceptor::builder(identity);
        builder.min_protocol_version(Some(native_tls::Protocol::Tlsv12));
        builder.max_protocol_version(Some(native_tls::Protocol::Tlsv12));
        let acceptor = tokio_native_tls::TlsAcceptor::from(builder.build().unwrap());
        let mut stream = acceptor.accept(server_socket).await.unwrap();
        let mut request = Vec::new();
        let mut bytes = [0u8; 1024];
        while !request.ends_with(b"\r\n\r\n") {
            let n = stream.read(&mut bytes).await.unwrap();
            assert!(n > 0 && request.len() + n <= 4096);
            request.extend_from_slice(&bytes[..n]);
        }
        assert_eq!(request, REQUEST);
        stream.write_all(&response).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let (prover_socket, verifier_socket) = tokio::io::duplex(1 << 20);
    let mut prover_session = Session::new(prover_socket.compat());
    let mut verifier_session = Session::new(verifier_socket.compat());
    let prover = prover_session.new_prover(ProverConfig::builder().build().unwrap()).unwrap();
    let verifier = verifier_session.new_verifier(
        VerifierConfig::builder().root_store(roots()).build().unwrap(),
    ).unwrap();
    let (prover_driver, prover_handle) = prover_session.split();
    let (verifier_driver, verifier_handle) = verifier_session.split();
    let prover_driver = tokio::spawn(prover_driver);
    let verifier_driver = tokio::spawn(verifier_driver);

    let prove = async {
        let prover = prover.commit(ProxyTlsConfig::builder()
            .server_name(DnsName::try_from(HOST).unwrap()).build().unwrap()).await.unwrap();
        let (connection, prover) = prover.connect(TlsClientConfig::builder()
            .server_name(ServerName::Dns(HOST.try_into().unwrap()))
            .root_store(roots()).build().unwrap()).unwrap();
        let prover_task = tokio::spawn(prover.into_future());
        let mut connection = connection.compat();
        connection.write_all(REQUEST).await.unwrap();
        let mut response = Vec::new();
        connection.read_to_end(&mut response).await.unwrap();
        connection.shutdown().await.unwrap();
        assert_eq!(response, expected_response);
        let mut prover = prover_task.await.unwrap().unwrap();
        let transcript = prover.transcript().clone();
        let mut commits = TranscriptCommitConfig::builder(&transcript);
        let kind = TranscriptCommitmentKind::Hash { alg: HashAlgId::SHA256 };
        let mut config = ProveConfig::builder(&transcript);
        config.server_identity();
        for (direction, ranges) in [(Direction::Sent, &disclosure.sent), (Direction::Received, &disclosure.recv)] {
            for range in ranges {
                match range.handler.action {
                    crate::HandlerAction::Hash { .. } => {
                        commits.commit_with_kind(&(range.start..range.end), direction, kind).unwrap();
                    }
                    crate::HandlerAction::Reveal => {
                        config.reveal(direction, &(range.start..range.end)).unwrap();
                    }
                }
            }
        }
        config.transcript_commit(commits.build().unwrap());
        let output = prover.prove(&config.build().unwrap()).await.unwrap();
        prover.close().await.unwrap();
        (transcript, output)
    };
    let verify = async {
        let VerifierCommitStart::Proxy(verifier) = verifier.commit().await.unwrap() else {
            panic!("expected Proxy mode")
        };
        let verifier = verifier.accept().await.unwrap().run(upstream_socket.compat()).await.unwrap();
        let (output, verifier) = verifier.verify().await.unwrap().accept().await.unwrap();
        let ServerName::Dns(server_name) = output.server_name.unwrap();
        assert_eq!(server_name.as_str(), HOST);
        assert_eq!(output.transcript.is_some(), mixed);
        assert_eq!(output.transcript_commitments.len(), expected_commitments);
        // Exercise exactly the production wrapper's post-verification adapter.
        let transcript = super::verified_transcript(
            output.transcript, &output.transcript_commitments, verifier.tls_transcript(),
        ).unwrap();
        verifier.close().await.unwrap();
        (transcript, output.transcript_commitments)
    };
    let ((private_transcript, mut prover_output), (public_transcript, mut commitments)) = tokio::join!(prove, verify);
    prover_handle.close();
    verifier_handle.close();
    prover_driver.await.unwrap().unwrap();
    verifier_driver.await.unwrap().unwrap();
    server.await.unwrap();

    // Core stores commitment requests in a HashSet. Intentionally reorder both
    // collections: neither input order nor output array position is a binding.
    prover_output.transcript_secrets.reverse();
    commitments.reverse();
    assert_eq!(commitments.len(), expected_commitments);
    assert_eq!(prover_output.transcript_secrets.len(), expected_commitments);
    assert_eq!(commitments.len(), prover_output.transcript_commitments.len());
    assert_eq!(public_transcript.len_sent(), private_transcript.sent().len());
    assert_eq!(public_transcript.len_received(), private_transcript.received().len());
    assert!(crate::verify_reveal_config(&disclosure, &public_transcript, &commitments).is_ok());
    for (direction, ranges, bytes, public, authenticated) in [
        (Direction::Sent, &disclosure.sent, private_transcript.sent(), public_transcript.sent_unsafe(), public_transcript.sent_authed()),
        (Direction::Received, &disclosure.recv, private_transcript.received(), public_transcript.received_unsafe(), public_transcript.received_authed()),
    ] {
        let results = crate::process_ranges(ranges, public, direction, &commitments, "test", "test");
        assert_eq!(results.len(), ranges.len());
        let mut covered = 0;
        for (range, result) in ranges.iter().zip(&results) {
            assert_eq!(range.start, covered);
            covered = range.end;
            let revealed = matches!(range.handler.action, crate::HandlerAction::Reveal);
            for position in range.start..range.end {
                assert_eq!(authenticated.contains(&position), revealed);
                assert_eq!(public[position], if revealed { bytes[position] } else { 0 });
            }
            if revealed {
                assert_eq!(result.value.as_bytes(), &bytes[range.start..range.end]);
                continue;
            }
            let idx = rangeset::set::RangeSet::from(range.start..range.end);
            let matches: Vec<_> = commitments.iter().filter_map(|commitment| match commitment {
                TranscriptCommitment::Hash(hash) if hash.direction == direction && hash.idx == idx
                    && hash.hash.alg == HashAlgId::SHA256 => Some(hash),
                _ => None,
            }).collect();
            assert_eq!(matches.len(), 1);
            let commitment = matches[0];
            let proved_matches = prover_output.transcript_commitments.iter().filter(|proved|
                matches!(proved, TranscriptCommitment::Hash(hash) if hash == commitment)).count();
            assert_eq!(proved_matches, 1);
            let secrets: Vec<_> = prover_output.transcript_secrets.iter().filter_map(|secret| match secret {
                TranscriptSecret::Hash(secret) if secret.direction == direction && secret.idx == idx
                    && secret.alg == HashAlgId::SHA256 => Some(secret),
                _ => None,
            }).collect();
            assert_eq!(secrets.len(), 1);
            assert_eq!(secrets[0].blinder.as_bytes().len(), 16);
            let digest = Sha256::new().chain_update(&bytes[range.start..range.end])
                .chain_update(secrets[0].blinder.as_bytes()).finalize();
            assert_eq!(commitment.hash.value.as_bytes(), digest.as_slice());
            let expected_hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            assert_eq!(result.value, expected_hex);
        }
        assert_eq!(covered, bytes.len());
        let rendered = serde_json::to_string(&results).unwrap();
        for secret in ["private-project", "private-user", "synthetic-secret", "2026-10-13T00:00:00Z"] {
            assert!(!rendered.contains(secret));
        }
    }
    if mixed {
        for alteration in 0..4 {
            let mut invalid = crate::RevealConfig { sent: disclosure.sent.clone(), recv: disclosure.recv.clone() };
            let range = invalid.sent.iter_mut().find(|range|
                matches!(range.handler.action, crate::HandlerAction::Hash { .. })).unwrap();
            match alteration {
                0 => range.end += 1,
                1 => range.handler.action = crate::HandlerAction::Hash { algorithm: crate::HashAlgorithm::Blake3 },
                2 => range.handler.handler_type = crate::HandlerType::Recv,
                3 => range.handler.action = crate::HandlerAction::Reveal,
                _ => unreachable!(),
            }
            assert!(crate::verify_reveal_config(&invalid, &public_transcript, &commitments).is_err());
        }
    }
}

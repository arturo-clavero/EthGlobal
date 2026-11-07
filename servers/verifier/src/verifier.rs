use crate::ws::TungsteniteStream;
use eyre::eyre;
use tlsn::{
    config::verifier::VerifierConfig,
    connection::{DnsName, ServerName},
    transcript::{ContentType, PartialTranscript, Record, TlsTranscript, TranscriptCommitment},
    verifier::{state, Verifier, VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
    Session, SessionHandle,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::oneshot;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{debug, info};

/// One verified proof of a session (a session may verify several).
pub struct RevealOutput {
    /// The server name, when this proof proved the server identity (the first
    /// proof of a session does; later ones may not).
    pub server_name: Option<DnsName>,
    pub transcript: PartialTranscript,
    pub transcript_commitments: Vec<TranscriptCommitment>,
}

/// A verifier session after the TLS connection, ready to verify one or more
/// proofs of the same transcript (`reveal`), then `finish`. The upstream flow
/// is one `reveal` and `finish`.
pub struct CommittedSession {
    verifier: Option<Verifier<state::Committed>>,
    handle: SessionHandle,
    driver_task: tokio::task::JoinHandle<Result<(), String>>,
    reveals: usize,
}

/// Core verifier logic up to the end of the TLS connection.
/// Supports both MPC and Proxy modes — the prover picks via its commit config.
///
/// `_proxy_socket_rx` is a leftover from the previous proxy plumbing
/// (`/proxy?sessionId=…`). The current `tlsn` API tunnels prover↔verifier proxy
/// traffic through the existing session multiplexer, so this channel is
/// unused. Kept on the signature to avoid rippling changes through `main.rs`
/// until that endpoint is removed.
pub async fn setup<T: AsyncWrite + AsyncRead + Send + Unpin + 'static>(
    socket: T,
    max_sent_data: usize,
    max_recv_data: usize,
    _proxy_socket_rx: Option<oneshot::Receiver<TungsteniteStream>>,
    settings: &crate::settings::Settings,
) -> Result<CommittedSession, eyre::ErrReport> {
    info!(
        "Starting verification with maxSentData={}, maxRecvData={}",
        max_sent_data, max_recv_data
    );

    // Create a session with the prover
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();

    // Spawn the session driver to run in the background
    let driver_task = tokio::spawn(async move {
        let result = driver.await;
        match &result {
            Ok(_) => tracing::info!("verifier session driver completed normally (mux closed)"),
            Err(e) => tracing::error!("verifier session driver error: {e}"),
        }
        result.map(|_| ()).map_err(|e| e.to_string())
    });

    let verifier_config = VerifierConfig::builder()
        .root_store(root_store(settings))
        .build()
        .map_err(|e| eyre!("Failed to build verifier config: {}", e))?;

    let verifier = handle
        .new_verifier(verifier_config)
        .map_err(|e| eyre!("Failed to create verifier: {}", e))?;

    info!("Starting TLS commitment protocol");

    // Run the commitment protocol — the prover's config tells us which mode.
    let verifier = match verifier
        .commit()
        .await
        .map_err(|e| eyre!("Commitment failed: {}", e))?
    {
        VerifierCommitStart::Mpc(verifier) => {
            let cfg = verifier.config();
            if cfg.max_sent_data() > max_sent_data {
                return Err(eyre!(
                    "Prover requested max_sent_data {} exceeds limit {}",
                    cfg.max_sent_data(),
                    max_sent_data
                ));
            }
            if cfg.max_recv_data() > max_recv_data {
                return Err(eyre!(
                    "Prover requested max_recv_data {} exceeds limit {}",
                    cfg.max_recv_data(),
                    max_recv_data
                ));
            }
            info!(
                "Accepting MPC TLS commitment with max_sent={}, max_recv={}",
                cfg.max_sent_data(),
                cfg.max_recv_data()
            );

            verifier
                .accept()
                .await
                .map_err(|e| eyre!("Accept failed: {}", e))?
                .run()
                .await
                .map_err(|e| eyre!("Run failed: {}", e))?
        }
        VerifierCommitStart::Proxy(verifier) => {
            let host = verifier.config().server_name().as_str().to_string();
            info!("Accepting Proxy TLS commitment for server: {}", host);

            let server_addr = dial_address(settings, &host);
            let server_stream = tokio::net::TcpStream::connect(&server_addr)
                .await
                .map_err(|e| eyre!("Failed to connect to target server {}: {}", server_addr, e))?;
            info!("Connected to target server {}", server_addr);

            verifier
                .accept()
                .await
                .map_err(|e| eyre!("Accept failed: {}", e))?
                .run(server_stream.compat())
                .await
                .map_err(|e| eyre!("Run failed: {}", e))?
        }
    };

    info!("TLS connection complete, starting verification");

    Ok(CommittedSession {
        verifier: Some(verifier),
        handle,
        driver_task,
        reveals: 0,
    })
}

impl CommittedSession {
    /// Proofs verified so far.
    pub fn reveals(&self) -> usize {
        self.reveals
    }

    /// Verifies ONE prove request of the prover. On success the session stays
    /// open for the next proof. On any error the session is closed (`finish`
    /// then only waits for the driver).
    pub async fn reveal(&mut self) -> Result<RevealOutput, eyre::ErrReport> {
        let verifier = self
            .verifier
            .take()
            .ok_or_else(|| eyre!("the verifier session is closed"))?;
        let result = self.reveal_inner(verifier).await;
        if result.is_err() {
            self.handle.close();
        }
        result
    }

    async fn reveal_inner(
        &mut self,
        verifier: Verifier<state::Committed>,
    ) -> Result<RevealOutput, eyre::ErrReport> {
        // Verify the proof
        let verifier = verifier
            .verify()
            .await
            .map_err(|e| eyre!("Verification failed: {}", e))?;

        let (
            VerifierOutput {
                server_name,
                transcript,
                transcript_commitments,
                ..
            },
            verifier,
        ) = verifier
            .accept()
            .await
            .map_err(|e| eyre!("Accept verification failed: {}", e))?;
        // A hash-only proof reveals no plaintext, so `transcript` is `None`:
        // rebuild its (all-zero) shape from the authenticated TLS records.
        let transcript = verified_transcript(
            transcript,
            &transcript_commitments,
            verifier.tls_transcript(),
        );
        self.verifier = Some(verifier);
        self.reveals += 1;

        info!("verify() returned successfully (proof {})", self.reveals);

        let transcript = transcript
            .ok_or_else(|| eyre!("prover should have revealed or committed transcript data"))?;
        debug!("transcript: {:?}", &transcript);

        let sent = transcript.sent_unsafe().to_vec();
        let received = transcript.received_unsafe().to_vec();

        let server_name = server_name.map(|ServerName::Dns(dns_name)| dns_name);
        info!("Server name verified: {:?}", server_name);

        info!("============================================");
        info!("Verification successful!");
        info!("============================================");

        info!("Sent data: {:?}", bytes_to_redacted_string(&sent, "\u{2588}")?);
        info!(
            "Received data: {:?}",
            bytes_to_redacted_string(&received, "\u{2588}")?
        );

        info!(
            "Hash commitments: {} (sent+recv)",
            transcript_commitments.len()
        );

        Ok(RevealOutput {
            server_name,
            transcript,
            transcript_commitments,
        })
    }

    /// Closes the verifier and the session and waits for the session driver.
    pub async fn finish(mut self) -> Result<(), eyre::ErrReport> {
        if let Some(verifier) = self.verifier.take() {
            // Close the verifier
            verifier
                .close()
                .await
                .map_err(|e| eyre!("Failed to close verifier: {}", e))?;
        }

        // Close the session handle
        self.handle.close();

        // Wait for the driver to complete
        self.driver_task
            .await
            .map_err(|e| eyre!("Driver task failed: {}", e))?
            .map_err(|e| eyre!("Session driver error: {}", e))?;

        info!("verifier session closed after {} proof(s)", self.reveals);
        Ok(())
    }
}

/// The root store server identities are checked against (Mozilla's; tests add
/// their fixture CA).
fn root_store(_settings: &crate::settings::Settings) -> RootCertStore {
    #[cfg(test)]
    if let Some(roots) = &_settings.test_roots {
        return RootCertStore {
            roots: roots.iter().map(|der| tlsn::webpki::CertificateDer(der.clone())).collect(),
        };
    }
    RootCertStore::mozilla()
}

/// Where a Proxy-mode session dials `host` (port 443; tests: their fixture server).
fn dial_address(_settings: &crate::settings::Settings, host: &str) -> String {
    #[cfg(test)]
    if let Some(addr) = &_settings.test_dial {
        return addr.clone();
    }
    format!("{}:443", host)
}

/// The proof's transcript, or for a proof with hash commitments and nothing
/// revealed, an all-zero transcript of the authenticated lengths.
fn verified_transcript(
    transcript: Option<PartialTranscript>,
    commitments: &[TranscriptCommitment],
    tls_transcript: &TlsTranscript,
) -> Option<PartialTranscript> {
    transcript.or_else(|| {
        (!commitments.is_empty())
            .then(|| redacted_transcript(tls_transcript.sent(), tls_transcript.recv()))
    })
}

fn redacted_transcript(sent: &[Record], received: &[Record]) -> PartialTranscript {
    // Match tlsn 47aee45 verifier/verify.rs::collect_ciphertext exactly. Its
    // TLS 1.2 record builder splits nonce/tag out of Record.ciphertext; the
    // remaining ApplicationData length is the authenticated plaintext length.
    // Do not use raw wire-record lengths or prover-selected commitment ends.
    let [sent_len, received_len] = [sent, received].map(|records| {
        records
            .iter()
            .filter(|record| record.typ == ContentType::ApplicationData)
            .map(|record| record.ciphertext.len())
            .sum()
    });
    PartialTranscript::new(sent_len, received_len)
}

/// Compress long sequences of redacted emojis for better readability
#[allow(unused)]
fn compress_redacted_sequences(text: String) -> String {
    let re = regex::Regex::new(r"\u{2588}{5,}").unwrap();
    re.replace_all(&text, "\u{2588}\u{2026}\u{2588}").to_string()
}

/// Render redacted bytes as block characters.
fn bytes_to_redacted_string(bytes: &[u8], to: &str) -> Result<String, eyre::ErrReport> {
    Ok(String::from_utf8(bytes.to_vec())
        .map_err(|err| eyre!("Failed to parse bytes to redacted string: {err}"))?
        .replace('\0', to))
}

#[cfg(test)]
mod private_commitments_tests {
    use super::redacted_transcript;
    use rangeset::set::RangeSet;
    use tlsn::{
        hash::{HashAlgId, TypedHash},
        transcript::{hash::PlaintextHash, ContentType, Direction, Record, TranscriptCommitment},
    };

    fn record(typ: ContentType, bytes: &[u8]) -> Record {
        Record {
            seq: 1,
            typ,
            // Even if a caller supplies plaintext, the fallback must never copy it.
            plaintext: Some(bytes.to_vec()),
            explicit_nonce: vec![0; 8],
            ciphertext: vec![0xa5; bytes.len()],
            tag: Some(vec![0; 16]),
        }
    }

    #[test]
    fn lengths_follow_authenticated_application_records_without_copying_plaintext() {
        let sent = [
            record(ContentType::Handshake, b"handshake"),
            record(ContentType::ApplicationData, b"private request"),
            record(ContentType::ApplicationData, b"continuation"),
            record(ContentType::Alert, b"alert"),
        ];
        let recv = [record(ContentType::ApplicationData, b"private response")];
        let transcript = redacted_transcript(&sent, &recv);
        assert_eq!(transcript.len_sent(), b"private requestcontinuation".len());
        assert_eq!(transcript.len_received(), b"private response".len());
        assert!(transcript.sent_unsafe().iter().all(|byte| *byte == 0));
        assert!(transcript.received_unsafe().iter().all(|byte| *byte == 0));
        assert!(transcript.sent_authed().is_empty());
        assert!(transcript.received_authed().is_empty());

        // A commitment ending early must not shorten the authoritative length
        // or be accepted under an ALL handler, even with zero revealed bytes.
        for end in [transcript.len_sent() - 1, transcript.len_sent()] {
            let commitments = [TranscriptCommitment::Hash(PlaintextHash {
                direction: Direction::Sent,
                idx: RangeSet::from(0..end),
                hash: TypedHash {
                    alg: HashAlgId::SHA256,
                    value: vec![0xab; 32].try_into().unwrap(),
                },
            })];
            let config = serde_json::from_value(serde_json::json!({
                "sent": [{"start": 0, "end": end, "handler": {
                    "type": "SENT", "part": "ALL",
                    "action": {"kind": "HASH", "algorithm": "SHA256"}
                }}],
                "recv": []
            })).unwrap();
            assert_eq!(
                crate::verify_reveal_config(&config, &transcript, &commitments).is_ok(),
                end == transcript.len_sent()
            );
        }
    }
}

#[cfg(test)]
#[path = "tests/private_proxy_test.rs"]
mod private_proxy_tests;

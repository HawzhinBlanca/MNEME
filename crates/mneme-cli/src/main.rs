//! `mneme` CLI — adoption-layer fail-closed gate (blueprint §14.2).

mod attest;
mod cert;
mod determinism;
mod pace;
mod replay;
mod robr;
mod shapley;

use clap::{Parser, Subcommand, ValueEnum};
use mneme_cap::agent_cap;
use mneme_core::{
    DistanceMetric, Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Procedure,
    ProcedureAlgo, Query, RetrievalProofLevel, TrustTier,
};
use mneme_core::{ForgetProof, encode_forget_proof};
use mneme_crypto::{EnvelopeKeyVault, KeyPair, TrustConfig};
use mneme_store::{Store, repair_store};
use mneme_verify::verify_store;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "mneme",
    version,
    about = "Verifiable memory substrate — fail-closed verify, recall, forget, merge",
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Operator seed as 32-byte hex (64 hex chars), e.g. `00..01`; required unless MNEME_KMS_MASTER_KEY_HEX is set to seal generated custody
    #[arg(long, global = true, env = "MNEME_OPERATOR_SEED")]
    operator_seed: Option<String>,

    /// Key vault backend: file (default) or envelope (uses MNEME_KMS_MASTER_KEY_HEX)
    #[arg(long, global = true, env = "MNEME_KEY_VAULT", default_value = "file")]
    vault: VaultArg,
}

#[derive(Subcommand)]
enum Commands {
    /// Fail-closed: exit 0 iff root and reachable proofs verify (§14.2)
    Verify {
        store: PathBuf,
        /// Optional trusted HEAD preimage hash (64 hex) carried out-of-band; rejects
        /// a full-snapshot rollback that is otherwise indistinguishable from disk (§2.4).
        #[arg(long = "pin-root")]
        pin_root: Option<String>,
    },
    /// [Not yet implemented] Print provenance, writers, tiers, tombstones for a root checkpoint
    Audit { root: PathBuf },
    /// Key recall under min trust tier (verified)
    Recall {
        store: PathBuf,
        #[arg(short = 'q', long)]
        query: String,
        #[arg(long = "min-tier", default_value = "trusted")]
        min_tier: TrustTierArg,
        /// Logical key namespace (default: user)
        #[arg(long, default_value = "user")]
        namespace: String,
        /// Logical key name (defaults to --query value)
        #[arg(long)]
        key: Option<String>,
        /// Optional trusted HEAD preimage hash (64 hex) carried out-of-band; rejects
        /// a full-snapshot rollback that is otherwise indistinguishable from disk (§2.4).
        #[arg(long = "pin-root")]
        pin_root: Option<String>,
    },
    /// Remember one episodic entry by logical key
    Remember {
        store: PathBuf,
        /// Logical key namespace (default: user)
        #[arg(long, default_value = "user")]
        namespace: String,
        /// Logical key name
        #[arg(long)]
        name: String,
        /// UTF-8 body to store
        #[arg(long)]
        body: String,
    },
    /// Cryptographic forget (shred)
    Forget {
        store: PathBuf,
        #[arg(long)]
        key: String,
        #[arg(long, default_value = "shred")]
        mode: ForgetModeArg,
        /// Write a self-contained ForgetProof CBOR to PATH (shred mode only)
        #[arg(long = "emit-proof")]
        emit_proof: Option<PathBuf>,
    },
    /// Clear `.incomplete` when HEAD-consistent; sweep unreferenced object blobs
    Repair { store: PathBuf },
    /// Deterministic MST merge of two stores
    Merge { store_a: PathBuf, store_b: PathBuf },
    /// Network anti-entropy over canonical §11 WebSocket sync (blueprint §11)
    Sync {
        #[command(subcommand)]
        command: SyncCommands,
    },
    /// Emit a Sigstore-signable attestation over a root (§15.2)
    Attest { root: PathBuf },
    /// Emit Cognition Certificate v1 for a semantic recall (Phase I)
    Certify {
        store: PathBuf,
        #[arg(long, default_value = "cert.cbor")]
        out: PathBuf,
        #[arg(long, default_value = "0,0")]
        components: String,
        #[arg(long, default_value_t = 2)]
        dim: u16,
        #[arg(long, default_value_t = 0)]
        scale: i8,
        #[arg(long = "proof-level", default_value = "exact-dominance")]
        proof_level: ProofLevelArg,
    },
    /// Offline verify Cognition Certificate v1 (Phase I)
    VerifyCert {
        cert: PathBuf,
        /// Enable Trick #1 audit-beacon spot-check (requires `audit_beacon` on cert)
        #[arg(long)]
        audit: bool,
        /// Enable Trick #4 Byzantine inference consistency (requires field 8 on cert)
        #[arg(long)]
        byzantine: bool,
        /// Store directory for true-distance recompute when audit is selected
        #[arg(long)]
        store: Option<PathBuf>,
        /// Query embedding components for audit recompute (e.g. `0,0`)
        #[arg(long, default_value = "0,0")]
        components: String,
        #[arg(long, default_value_t = 2)]
        dim: u16,
        #[arg(long, default_value_t = 0)]
        scale: i8,
        #[arg(long = "ef-search", default_value_t = 64)]
        ef_search: u32,
        #[arg(long, default_value_t = 1)]
        k: u32,
    },
    /// Certified Counterfactual Replay (weak mode): assemble a verified context from
    /// KEYS with and without one entry; emit a signed offline-verifiable certificate
    Replay {
        store: PathBuf,
        /// Comma-separated logical key names forming the context, in order
        #[arg(long)]
        keys: String,
        /// Object id (64 hex chars) to exclude in the counterfactual pass
        #[arg(long)]
        without: String,
        /// Logical key namespace (default: user)
        #[arg(long, default_value = "user")]
        namespace: String,
        #[arg(long = "min-tier", default_value = "trusted")]
        min_tier: TrustTierArg,
        /// Output path for the replay certificate
        #[arg(long, default_value = "replay-cert.bin")]
        out: PathBuf,
    },
    /// Offline verify a replay certificate (signature + internal consistency)
    VerifyReplay {
        cert: PathBuf,
        /// Optional pinned operator public key (64 hex chars) carried out-of-band
        #[arg(long = "operator-pk")]
        operator_pk: Option<String>,
    },
    /// CCR-Shapley: certified Monte-Carlo attribution of a verified context
    /// against a supplied judge command (hash-bound, execution not attested)
    Shapley {
        store: PathBuf,
        /// Comma-separated logical key names forming the context, in order
        #[arg(long)]
        keys: String,
        /// Judge command (split on whitespace); context piped on stdin
        #[arg(long)]
        judge: String,
        /// Permutation samples (deterministic from --seed)
        #[arg(long, default_value_t = 16)]
        samples: u32,
        /// Sampling seed (64 hex chars)
        #[arg(
            long,
            default_value = "0000000000000000000000000000000000000000000000000000000000000042"
        )]
        seed: String,
        /// Logical key namespace (default: user)
        #[arg(long, default_value = "user")]
        namespace: String,
        #[arg(long = "min-tier", default_value = "trusted")]
        min_tier: TrustTierArg,
        /// Output path for the attribution certificate
        #[arg(long, default_value = "shapley-cert.bin")]
        out: PathBuf,
    },
    /// Offline verify a CCR-Shapley certificate (signature + consistency)
    VerifyShapley {
        cert: PathBuf,
        /// Optional pinned operator public key (64 hex chars)
        #[arg(long = "operator-pk")]
        operator_pk: Option<String>,
    },
    /// ROBR-1: emit a Recall-to-Output Binding Receipt — bind a model output
    /// commitment to the signed memory root, prompt, weight measurement, sampling
    /// params, and the verified context assembled from fail-closed recalls.
    Robr {
        store: PathBuf,
        /// Comma-separated logical key names whose verified recalls form the context
        #[arg(long = "keys")]
        keys: String,
        #[arg(long = "namespace", default_value = "user")]
        namespace: String,
        #[arg(long = "min-tier", value_enum, default_value_t = TrustTierArg::Quarantine)]
        min_tier: TrustTierArg,
        /// Prompt presented to the model (hashed into the envelope)
        #[arg(long = "prompt")]
        prompt: String,
        /// Operator-asserted model weight measurement (64 hex chars)
        #[arg(long = "weight-measurement")]
        weight_measurement: String,
        /// Canonical sampling params, e.g. "model=…;temp=0;top_p=1;seed=42"
        #[arg(long = "sampling")]
        sampling: String,
        /// File holding the produced output tokens (committed to via BLAKE3)
        #[arg(long = "output-file")]
        output_file: PathBuf,
        #[arg(long = "out")]
        out: PathBuf,
    },
    /// Offline verify a ROBR binding receipt (signature + envelope consistency)
    VerifyRobr {
        cert: PathBuf,
        /// Optional pinned operator public key (64 hex chars)
        #[arg(long = "operator-pk")]
        operator_pk: Option<String>,
    },
    /// Initialize a new store at PATH
    Init { path: PathBuf },
    /// Determinism foundation gate (§17.7)
    Determinism {
        #[command(subcommand)]
        command: DeterminismCommands,
    },
    /// VCP A1: BLAKE3 sequential pace log (min-interval only; not wall time)
    Pace {
        #[command(subcommand)]
        command: PaceCommands,
    },
}

#[derive(Subcommand)]
enum SyncCommands {
    /// Pull peer object delta into STORE via ws://HOST/v1/sync (DiffReq/WantObjects protocol)
    Pull {
        store: PathBuf,
        /// WebSocket URL of peer mnemed sync endpoint (e.g. ws://127.0.0.1:7845/v1/sync)
        #[arg(long = "peer-url")]
        peer_url: String,
    },
}

#[derive(Subcommand)]
enum PaceCommands {
    /// Measure alg=2 iterations-per-tick on this host (advisory calibration)
    Calibrate {
        #[arg(long)]
        out: PathBuf,
        #[arg(long = "target-ms", default_value_t = 1000)]
        target_ms: u64,
    },
    /// Append one paced segment to a log (creates log if missing)
    Run {
        #[arg(long)]
        log: PathBuf,
        #[arg(long)]
        calib: Option<PathBuf>,
        #[arg(long)]
        genesis: Option<String>,
        #[arg(long)]
        iterations: Option<u64>,
        #[arg(long)]
        label: Option<String>,
    },
    /// Offline verify chain integrity and optional minimum iterations per gap
    Verify {
        log: PathBuf,
        #[arg(long = "min-iterations")]
        min_iterations: Option<u64>,
    },
}

#[derive(Subcommand)]
enum DeterminismCommands {
    /// Build fixture store twice; assert byte-identical roots/receipts
    FoundationGate {
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "1970-01-01T00:00:00Z")]
        timestamp: String,
    },
    /// Verify a foundation.report.json from foundation-gate
    FoundationVerify {
        report: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum TrustTierArg {
    Quarantine,
    Working,
    Trusted,
    Identity,
}

impl From<TrustTierArg> for TrustTier {
    fn from(v: TrustTierArg) -> Self {
        match v {
            TrustTierArg::Quarantine => TrustTier::Quarantine,
            TrustTierArg::Working => TrustTier::Working,
            TrustTierArg::Trusted => TrustTier::Trusted,
            TrustTierArg::Identity => TrustTier::Identity,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum ForgetModeArg {
    Shred,
    Redact,
}

#[derive(Clone, Copy, ValueEnum, Default)]
enum ProofLevelArg {
    #[default]
    ExactDominance,
    HnswAuditOnDemand,
    CompleteTopK,
}

impl From<ProofLevelArg> for RetrievalProofLevel {
    fn from(v: ProofLevelArg) -> Self {
        match v {
            ProofLevelArg::ExactDominance => RetrievalProofLevel::ExactDominance,
            ProofLevelArg::HnswAuditOnDemand => RetrievalProofLevel::HnswAuditOnDemand,
            ProofLevelArg::CompleteTopK => RetrievalProofLevel::CompleteTopK,
        }
    }
}

#[derive(Clone, Copy, ValueEnum)]
enum VaultArg {
    File,
    Envelope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliErrorKind {
    Usage,
    StoreUnavailable,
    VerifyFailed(MnemeError),
    Kernel(MnemeError),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(kind) => {
            let (code, msg) = match kind {
                CliErrorKind::Usage => (2, "invalid usage".to_string()),
                CliErrorKind::StoreUnavailable => (
                    3,
                    "store kernel not available: build mneme-store and re-run".to_string(),
                ),
                CliErrorKind::VerifyFailed(e) => (4, format!("verify failed: {e}")),
                CliErrorKind::Kernel(e) => (5, format!("{e}")),
            };
            eprintln!("mneme: {msg}");
            ExitCode::from(code)
        }
    }
}

fn run(cli: Cli) -> Result<(), CliErrorKind> {
    match cli.command {
        Commands::Replay {
            store,
            keys,
            without,
            namespace,
            min_tier,
            out,
        } => {
            let key_names: Vec<String> = keys
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if key_names.is_empty() {
                eprintln!("mneme: replay requires --keys with at least one key");
                return Err(CliErrorKind::Usage);
            }
            let excluded = parse_seed_hex(&without)?;
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let mut mneme_store = open_store(&store, operator.clone(), cli.vault)?;
            let cap =
                agent_cap(&operator, operator.public_key_bytes()).map_err(CliErrorKind::Kernel)?;
            mneme_store
                .trust_mut()
                .authorized_writers
                .push(operator.public_key_bytes());
            // Factual pass: every context entry comes through fail-closed verified recall.
            let mut factual: Vec<([u8; 32], Vec<u8>)> = Vec::new();
            for name in &key_names {
                let q = Query {
                    logical_key: LogicalKey {
                        namespace: namespace.clone(),
                        name: name.clone(),
                    },
                    min_tier: min_tier.into(),
                    embedding: None,
                };
                let entries = mneme_store
                    .recall_verified_default(&q, &cap)
                    .map_err(CliErrorKind::Kernel)?;
                for e in entries {
                    factual.push((e.id.0, e.plaintext.clone()));
                }
            }
            // Counterfactual pass: identical context minus the excluded entry.
            let counterfactual: Vec<([u8; 32], Vec<u8>)> = factual
                .iter()
                .filter(|(id, _)| id != &excluded)
                .cloned()
                .collect();
            let differs = factual.len() != counterfactual.len();
            let root = mneme_store.current_root().map_err(CliErrorKind::Kernel)?;
            let cert = replay::ReplayCertV1 {
                root_seq: root.sequence,
                root_preimage: root.preimage_hash,
                namespace,
                keys: key_names,
                min_tier: {
                    let t: TrustTier = min_tier.into();
                    t as u8
                },
                excluded,
                factual_ids: factual.iter().map(|(id, _)| *id).collect(),
                counterfactual_ids: counterfactual.iter().map(|(id, _)| *id).collect(),
                factual_hash: replay::context_hash(&factual),
                counterfactual_hash: replay::context_hash(&counterfactual),
                differs,
                operator_pk: operator.public_key_bytes(),
                sig: [0u8; 64],
            };
            let wire = cert
                .sign_and_encode(&operator)
                .map_err(CliErrorKind::Kernel)?;
            std::fs::write(&out, &wire).map_err(|_| CliErrorKind::Usage)?;
            println!(
                "replay cert written: {} ({} bytes) root_seq={} entries={} differs={}",
                out.display(),
                wire.len(),
                root.sequence,
                factual.len(),
                differs
            );
            println!("honesty: {}", replay::REPLAY_HONESTY);
            Ok(())
        }
        Commands::VerifyReplay { cert, operator_pk } => {
            let wire = std::fs::read(&cert).map_err(|_| CliErrorKind::Usage)?;
            let pinned = match operator_pk {
                Some(hex) => Some(parse_seed_hex(&hex)?),
                None => None,
            };
            let parsed = replay::ReplayCertV1::verify(&wire, pinned.as_ref())
                .map_err(CliErrorKind::VerifyFailed)?;
            println!(
                "verify-replay ok: root_seq={} keys={} factual_entries={} differs={} excluded={} operator_pk={}",
                parsed.root_seq,
                parsed.keys.len(),
                parsed.factual_ids.len(),
                parsed.differs,
                hex::encode(parsed.excluded),
                hex::encode(parsed.operator_pk)
            );
            if pinned.is_none() {
                println!(
                    "note: operator key not pinned — verified against the embedded key; confirm it out-of-band"
                );
            }
            println!("honesty: {}", replay::REPLAY_HONESTY);
            Ok(())
        }
        Commands::Shapley {
            store,
            keys,
            judge,
            samples,
            seed,
            namespace,
            min_tier,
            out,
        } => {
            let key_names: Vec<String> = keys
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if key_names.is_empty() || judge.trim().is_empty() || samples == 0 {
                eprintln!("mneme: shapley requires --keys, --judge, and --samples > 0");
                return Err(CliErrorKind::Usage);
            }
            let seed_bytes = parse_seed_hex(&seed)?;
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let mut mneme_store = open_store(&store, operator.clone(), cli.vault)?;
            let cap =
                agent_cap(&operator, operator.public_key_bytes()).map_err(CliErrorKind::Kernel)?;
            mneme_store
                .trust_mut()
                .authorized_writers
                .push(operator.public_key_bytes());
            let mut entries: Vec<([u8; 32], Vec<u8>)> = Vec::new();
            for name in &key_names {
                let q = Query {
                    logical_key: LogicalKey {
                        namespace: namespace.clone(),
                        name: name.clone(),
                    },
                    min_tier: min_tier.into(),
                    embedding: None,
                };
                let recalled = mneme_store
                    .recall_verified_default(&q, &cap)
                    .map_err(CliErrorKind::Kernel)?;
                for e in recalled {
                    entries.push((e.id.0, e.plaintext.clone()));
                }
            }
            let counts = shapley::sample_counts(&judge, &entries, &seed_bytes, samples)
                .map_err(CliErrorKind::Kernel)?;
            let root = mneme_store.current_root().map_err(CliErrorKind::Kernel)?;
            let cert = shapley::ShapleyCertV1 {
                root_seq: root.sequence,
                root_preimage: root.preimage_hash,
                namespace,
                keys: key_names.clone(),
                ids: entries.iter().map(|(id, _)| *id).collect(),
                judge_hash: shapley::judge_hash(&judge),
                seed: seed_bytes,
                samples,
                counts: counts.clone(),
                operator_pk: operator.public_key_bytes(),
                sig: [0u8; 64],
            };
            let wire = cert
                .sign_and_encode(&operator)
                .map_err(CliErrorKind::Kernel)?;
            std::fs::write(&out, &wire).map_err(|_| CliErrorKind::Usage)?;
            println!(
                "shapley cert written: {} ({} bytes) root_seq={} samples={}",
                out.display(),
                wire.len(),
                root.sequence,
                samples
            );
            for (idx, (id, _)) in entries.iter().enumerate() {
                println!(
                    "  {} marginal_impact={}/{}",
                    hex::encode(id),
                    counts[idx],
                    samples
                );
            }
            println!("honesty: {}", shapley::SHAPLEY_HONESTY);
            Ok(())
        }
        Commands::VerifyShapley { cert, operator_pk } => {
            let wire = std::fs::read(&cert).map_err(|_| CliErrorKind::Usage)?;
            let pinned = match operator_pk {
                Some(hex) => Some(parse_seed_hex(&hex)?),
                None => None,
            };
            let parsed = shapley::ShapleyCertV1::verify(&wire, pinned.as_ref())
                .map_err(CliErrorKind::VerifyFailed)?;
            println!(
                "verify-shapley ok: root_seq={} entries={} samples={} judge_hash={} operator_pk={}",
                parsed.root_seq,
                parsed.ids.len(),
                parsed.samples,
                hex::encode(parsed.judge_hash),
                hex::encode(parsed.operator_pk)
            );
            for (idx, id) in parsed.ids.iter().enumerate() {
                println!(
                    "  {} marginal_impact={}/{}",
                    hex::encode(id),
                    parsed.counts[idx],
                    parsed.samples
                );
            }
            if pinned.is_none() {
                println!(
                    "note: operator key not pinned — verified against the embedded key; confirm it out-of-band"
                );
            }
            println!("honesty: {}", shapley::SHAPLEY_HONESTY);
            Ok(())
        }
        Commands::Robr {
            store,
            keys,
            namespace,
            min_tier,
            prompt,
            weight_measurement,
            sampling,
            output_file,
            out,
        } => {
            let key_names: Vec<String> = keys
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if key_names.is_empty() {
                eprintln!("mneme: robr requires --keys with at least one key");
                return Err(CliErrorKind::Usage);
            }
            let weight = parse_seed_hex(&weight_measurement)?;
            let output = std::fs::read(&output_file).map_err(|_| CliErrorKind::Usage)?;
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let mut mneme_store = open_store(&store, operator.clone(), cli.vault)?;
            let cap =
                agent_cap(&operator, operator.public_key_bytes()).map_err(CliErrorKind::Kernel)?;
            mneme_store
                .trust_mut()
                .authorized_writers
                .push(operator.public_key_bytes());
            // Context: every entry comes through fail-closed verified recall.
            let mut context: Vec<([u8; 32], Vec<u8>)> = Vec::new();
            for name in &key_names {
                let q = Query {
                    logical_key: LogicalKey {
                        namespace: namespace.clone(),
                        name: name.clone(),
                    },
                    min_tier: min_tier.into(),
                    embedding: None,
                };
                let entries = mneme_store
                    .recall_verified_default(&q, &cap)
                    .map_err(CliErrorKind::Kernel)?;
                for e in entries {
                    context.push((e.id.0, e.plaintext.clone()));
                }
            }
            let root = mneme_store.current_root().map_err(CliErrorKind::Kernel)?;
            let prompt_hash = *blake3::hash(prompt.as_bytes()).as_bytes();
            let ctx_hash = robr::context_hash(&context);
            let env = robr::envelope_hash(
                &root.preimage_hash,
                &prompt_hash,
                &weight,
                &sampling,
                &ctx_hash,
            );
            let receipt = robr::RobrReceiptV1 {
                root_seq: root.sequence,
                root_preimage: root.preimage_hash,
                prompt_hash,
                weight_measurement: weight,
                sampling_params: sampling,
                context_ids: context.iter().map(|(id, _)| *id).collect(),
                context_hash: ctx_hash,
                envelope_hash: env,
                output_token_commit: *blake3::hash(&output).as_bytes(),
                operator_pk: operator.public_key_bytes(),
                sig: [0u8; 64],
            };
            let wire = receipt
                .sign_and_encode(&operator)
                .map_err(CliErrorKind::Kernel)?;
            std::fs::write(&out, &wire).map_err(|_| CliErrorKind::Usage)?;
            println!(
                "robr receipt written: {} ({} bytes) root_seq={} context_entries={} envelope={}",
                out.display(),
                wire.len(),
                root.sequence,
                context.len(),
                hex::encode(env)
            );
            println!("honesty: {}", robr::ROBR_HONESTY);
            Ok(())
        }
        Commands::VerifyRobr { cert, operator_pk } => {
            let wire = std::fs::read(&cert).map_err(|_| CliErrorKind::Usage)?;
            let pinned = match operator_pk {
                Some(hex) => Some(parse_seed_hex(&hex)?),
                None => None,
            };
            let parsed = robr::RobrReceiptV1::verify(&wire, pinned.as_ref())
                .map_err(CliErrorKind::VerifyFailed)?;
            println!(
                "verify-robr ok: root_seq={} context_entries={} envelope={} output_commit={} operator_pk={}",
                parsed.root_seq,
                parsed.context_ids.len(),
                hex::encode(parsed.envelope_hash),
                hex::encode(parsed.output_token_commit),
                hex::encode(parsed.operator_pk)
            );
            if pinned.is_none() {
                println!(
                    "note: operator key not pinned — verified against the embedded key; confirm it out-of-band"
                );
            }
            println!("honesty: {}", robr::ROBR_HONESTY);
            Ok(())
        }
        Commands::Init { path } => {
            if path.exists() {
                eprintln!("mneme: init path already exists: {}", path.display());
                return Err(CliErrorKind::Usage);
            }
            std::fs::create_dir_all(&path).map_err(|_| CliErrorKind::Usage)?;
            let operator = load_or_generate_operator(&path, cli.operator_seed.as_deref())?;
            create_store(&path, operator, cli.vault)?;
            println!("initialized store at {}", path.display());
            Ok(())
        }
        Commands::Verify { store, pin_root } => {
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let trust = TrustConfig::new(operator.public_key_bytes());
            let report = verify_store(&store, &trust).map_err(CliErrorKind::VerifyFailed)?;
            // §2.4 residual: reject a full-snapshot rollback against an out-of-band pin.
            if let Some(pin_hex) = pin_root {
                let expected = parse_seed_hex(&pin_hex)?;
                if report.root.preimage_hash != expected {
                    return Err(CliErrorKind::VerifyFailed(MnemeError::RootReplayed));
                }
            }
            println!(
                "verify ok: root seq {} objects {}",
                report.root.sequence, report.object_count
            );
            Ok(())
        }
        Commands::Recall {
            store,
            query,
            min_tier,
            namespace,
            key,
            pin_root,
        } => {
            if query.trim().is_empty() && key.is_none() {
                eprintln!("mneme: recall requires --query or --key");
                return Err(CliErrorKind::Usage);
            }
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let pin = match pin_root {
                Some(hex) => Some(parse_seed_hex(&hex)?),
                None => None,
            };
            let mut mneme_store = open_store_pinned(&store, operator.clone(), pin, cli.vault)?;
            let cap =
                agent_cap(&operator, operator.public_key_bytes()).map_err(CliErrorKind::Kernel)?;
            mneme_store
                .trust_mut()
                .authorized_writers
                .push(operator.public_key_bytes());
            let logical_key = LogicalKey {
                namespace,
                name: key.unwrap_or(query),
            };
            let q = Query {
                logical_key,
                min_tier: min_tier.into(),
                embedding: None,
            };
            let entries = mneme_store
                .recall_verified_default(&q, &cap)
                .map_err(CliErrorKind::Kernel)?;
            for e in entries {
                let body = String::from_utf8_lossy(&e.plaintext);
                println!("{}: {}", e.id, body);
            }
            Ok(())
        }
        Commands::Remember {
            store,
            namespace,
            name,
            body,
        } => {
            if namespace.trim().is_empty() || name.trim().is_empty() {
                eprintln!("mneme: remember requires non-empty --namespace and --name");
                return Err(CliErrorKind::Usage);
            }
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let mut mneme_store = open_store(&store, operator.clone(), cli.vault)?;
            let cap =
                agent_cap(&operator, operator.public_key_bytes()).map_err(CliErrorKind::Kernel)?;
            let draft = Draft {
                namespace,
                logical_name: name,
                kind: MemoryKind::Episodic,
                body: body.into_bytes(),
                parent_ids: vec![],
                session: [0xab; 16],
                trust_tier: Some(TrustTier::Trusted),
                embedding: None,
                valid_time_ms: None,
            };
            let (id, root) = mneme_store
                .remember(draft, &cap)
                .map_err(CliErrorKind::Kernel)?;
            println!(
                "remembered object_id={} root_preimage_hash={}",
                id,
                hex::encode(root.preimage_hash)
            );
            Ok(())
        }
        Commands::Repair { store } => {
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let report = repair_store(&store, &operator).map_err(CliErrorKind::Kernel)?;
            println!(
                "repair ok: cleared_incomplete={} orphans_removed={}",
                report.cleared_incomplete, report.orphans_removed
            );
            Ok(())
        }
        Commands::Forget {
            store,
            key,
            mode,
            emit_proof,
        } => {
            if key.trim().is_empty() {
                eprintln!("mneme: forget --key must not be empty");
                return Err(CliErrorKind::Usage);
            }
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let mut mneme_store = open_store(&store, operator.clone(), cli.vault)?;
            let cap =
                agent_cap(&operator, operator.public_key_bytes()).map_err(CliErrorKind::Kernel)?;
            let logical_key = parse_logical_key(&key);
            let forget_mode = match mode {
                ForgetModeArg::Shred => ForgetMode::Shred,
                ForgetModeArg::Redact => ForgetMode::Redact,
            };
            if let Some(path) = emit_proof {
                if !matches!(forget_mode, ForgetMode::Shred) {
                    eprintln!("mneme: --emit-proof requires shred mode");
                    return Err(CliErrorKind::Usage);
                }
                let proven = mneme_store
                    .forget_with_proof(
                        ForgetTarget::LogicalKey(logical_key),
                        &cap,
                        forget_mode,
                        None,
                    )
                    .map_err(CliErrorKind::Kernel)?;
                write_forget_proof(&path, &proven.proof)?;
                println!("forgot key {key}; proof written to {}", path.display());
            } else {
                mneme_store
                    .forget(ForgetTarget::LogicalKey(logical_key), &cap, forget_mode)
                    .map_err(CliErrorKind::Kernel)?;
                println!("forgot key {key}");
            }
            Ok(())
        }
        Commands::Sync { command } => match command {
            SyncCommands::Pull { store, peer_url } => {
                if peer_url.trim().is_empty() {
                    eprintln!("mneme: sync pull requires --peer-url");
                    return Err(CliErrorKind::Usage);
                }
                if !peer_url.starts_with("ws://") && !peer_url.starts_with("wss://") {
                    eprintln!("mneme: --peer-url must be a WebSocket URL (ws:// or wss://)");
                    return Err(CliErrorKind::Usage);
                }
                require_store_dir(&store)?;
                let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
                let mut mneme_store = open_store(&store, operator.clone(), cli.vault)?;
                let cap = agent_cap(&operator, operator.public_key_bytes())
                    .map_err(CliErrorKind::Kernel)?;
                let cap_b64 = mnemed::cap_to_b64(&cap).map_err(CliErrorKind::Kernel)?;
                let rt = tokio::runtime::Runtime::new().map_err(|_| CliErrorKind::Usage)?;
                let fetched = rt
                    .block_on(mnemed::sync_client::pull_canonical_with_cap(
                        &mut mneme_store,
                        &peer_url,
                        &cap_b64,
                    ))
                    .map_err(CliErrorKind::Kernel)?;
                let root = mneme_store.current_root().map_err(CliErrorKind::Kernel)?;
                println!(
                    "sync pull ok: fetched {} object(s); key_index_root={}",
                    fetched,
                    hex::encode(root.key_index_root)
                );
                Ok(())
            }
        },
        Commands::Merge { store_a, store_b } => {
            require_store_dir(&store_a)?;
            require_store_dir(&store_b)?;
            let operator = load_or_generate_operator(&store_a, cli.operator_seed.as_deref())?;
            let mut mneme_store = open_store(&store_a, operator, cli.vault)?;
            let root = mneme_store
                .merge_from_path(&store_b)
                .map_err(CliErrorKind::Kernel)?;
            println!(
                "merged root preimage_hash={}",
                hex::encode(root.preimage_hash)
            );
            Ok(())
        }
        Commands::Audit { root } => {
            // Validate the argument before reporting non-implementation: a missing root path is a
            // usage error (exit 2), matching `audit_missing_root_is_usage_error`. Only a present,
            // well-formed argument reaches the not-yet-implemented surface (exit 3).
            if !root.exists() {
                eprintln!("mneme: root checkpoint not found: {}", root.display());
                return Err(CliErrorKind::Usage);
            }
            eprintln!(
                "mneme: audit is not yet implemented (provenance/writer/tier/tombstone dump deferred)"
            );
            Err(CliErrorKind::StoreUnavailable)
        }
        Commands::Certify {
            store,
            out,
            components,
            dim,
            scale,
            proof_level,
        } => {
            require_store_dir(&store)?;
            let comps = parse_i16_list(&components)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let trust = TrustConfig::new(operator.public_key_bytes());
            let mneme_store = open_store(&store, operator.clone(), cli.vault)?;
            let cap =
                agent_cap(&operator, operator.public_key_bytes()).map_err(CliErrorKind::Kernel)?;
            cert::run_certify(
                &mneme_store,
                &trust,
                &cap,
                &comps,
                dim,
                scale,
                proof_level.into(),
                &out,
            )
            .map_err(CliErrorKind::VerifyFailed)?;
            println!("cognition certificate v1 written to {}", out.display());
            Ok(())
        }
        Commands::VerifyCert {
            cert,
            audit,
            byzantine,
            store,
            components,
            dim,
            scale,
            ef_search,
            k,
        } => {
            require_file_exists(&cert, "cognition certificate")?;
            let pk = if let Some(ref seed) = cli.operator_seed {
                let operator = KeyPair::from_seed(parse_seed_hex(seed)?);
                operator.public_key_bytes()
            } else {
                return Err(CliErrorKind::Usage);
            };
            let trust = TrustConfig::new(pk);
            let proc = Procedure {
                algo: ProcedureAlgo::Hnsw,
                ef_search,
                k,
                distance: DistanceMetric::SquaredL2I64,
                seed: 0,
            };
            if byzantine {
                let msg = cert::run_verify_cert_byzantine(&cert, &trust, &proc).map_err(|e| {
                    eprintln!("honesty: {}", cert::verify_cert_byzantine_honesty_footer());
                    CliErrorKind::VerifyFailed(e)
                })?;
                println!("{msg}");
            } else if audit {
                let store_path = store.as_deref();
                let query = cert::certify_embedding_from_components(
                    &parse_i16_list(&components)?,
                    dim,
                    scale,
                )
                .map_err(CliErrorKind::VerifyFailed)?;
                let msg = cert::run_verify_cert_audit(
                    &cert,
                    &trust,
                    &proc,
                    cert::VerifyCertAuditOptions {
                        store: store_path,
                        query: Some(&query),
                    },
                )
                .map_err(|e| {
                    eprintln!("honesty: {}", cert::verify_cert_audit_honesty_footer());
                    CliErrorKind::VerifyFailed(e)
                })?;
                println!("{msg}");
            } else {
                cert::run_verify_cert(&cert, &trust, &proc).map_err(CliErrorKind::VerifyFailed)?;
                println!("verify-cert ok: cognition certificate v1 valid offline");
            }
            Ok(())
        }
        Commands::Attest { root } => {
            require_file_exists(&root, "root checkpoint")?;
            let bytes = std::fs::read(&root).map_err(|_| CliErrorKind::Usage)?;
            let statement = attest::sigstore_statement(&bytes);
            println!(
                "{}",
                serde_json::to_string_pretty(&statement).map_err(|_| CliErrorKind::Usage)?
            );
            Ok(())
        }
        Commands::Determinism { command } => match command {
            DeterminismCommands::FoundationGate { out, timestamp } => {
                let operator_seed = cli
                    .operator_seed
                    .as_deref()
                    .map(parse_seed_hex)
                    .transpose()?;
                determinism::foundation_gate(&out, &timestamp, operator_seed)
                    .map_err(CliErrorKind::Kernel)?;
                println!("foundation-gate OK: {}", out.display());
                Ok(())
            }
            DeterminismCommands::FoundationVerify { report, output } => {
                determinism::foundation_verify(&report, &output).map_err(CliErrorKind::Kernel)?;
                println!("foundation-verify OK: {}", output.display());
                Ok(())
            }
        },
        Commands::Pace { command } => match command {
            PaceCommands::Calibrate { out, target_ms } => {
                pace::run_calibrate(&out, target_ms).map_err(pace_error_to_cli)?;
                Ok(())
            }
            PaceCommands::Run {
                log,
                calib,
                genesis,
                iterations,
                label,
            } => {
                pace::run_append(
                    &log,
                    calib.as_deref(),
                    genesis.as_deref(),
                    iterations,
                    label,
                )
                .map_err(pace_error_to_cli)?;
                Ok(())
            }
            PaceCommands::Verify {
                log,
                min_iterations,
            } => {
                require_file_exists(&log, "pace log")?;
                pace::run_verify(&log, min_iterations).map_err(pace_error_to_cli)?;
                Ok(())
            }
        },
    }
}

fn pace_error_to_cli(err: mneme_pace::PaceError) -> CliErrorKind {
    use mneme_pace::PaceError;
    match err {
        PaceError::EmptyLog | PaceError::GenesisMismatch => CliErrorKind::Usage,
        other => CliErrorKind::VerifyFailed(other.to_mneme()),
    }
}

fn parse_logical_key(key: &str) -> LogicalKey {
    if let Some((ns, name)) = key.split_once('/') {
        LogicalKey {
            namespace: ns.into(),
            name: name.into(),
        }
    } else {
        LogicalKey {
            namespace: "user".into(),
            name: key.into(),
        }
    }
}

fn create_store(path: &Path, operator: KeyPair, vault: VaultArg) -> Result<Store, CliErrorKind> {
    match vault {
        VaultArg::File => Store::create(path, operator).map_err(CliErrorKind::Kernel),
        VaultArg::Envelope => {
            let key_vault =
                Box::new(EnvelopeKeyVault::from_env(path).map_err(CliErrorKind::Kernel)?);
            Store::create_with_vault(path, operator, key_vault).map_err(CliErrorKind::Kernel)
        }
    }
}

fn open_store(path: &Path, operator: KeyPair, vault: VaultArg) -> Result<Store, CliErrorKind> {
    open_store_pinned(path, operator, None, vault)
}

fn open_store_pinned(
    path: &Path,
    operator: KeyPair,
    pinned_root: Option<[u8; 32]>,
    vault: VaultArg,
) -> Result<Store, CliErrorKind> {
    match vault {
        VaultArg::File => {
            Store::open_pinned(path, operator, pinned_root).map_err(CliErrorKind::Kernel)
        }
        VaultArg::Envelope => {
            let key_vault =
                Box::new(EnvelopeKeyVault::from_env(path).map_err(CliErrorKind::Kernel)?);
            Store::open_pinned_with_vault(path, operator, pinned_root, key_vault)
                .map_err(CliErrorKind::Kernel)
        }
    }
}

fn load_or_generate_operator(
    store: &Path,
    seed_hex: Option<&str>,
) -> Result<KeyPair, CliErrorKind> {
    mneme_crypto::load_or_generate_operator(store, seed_hex).map_err(operator_seed_error_to_cli)
}

fn operator_seed_error_to_cli(err: MnemeError) -> CliErrorKind {
    match err {
        MnemeError::CapMalformed => CliErrorKind::Usage,
        MnemeError::KeyVaultMissing => {
            eprintln!(
                "mneme: operator seed custody missing: provide --operator-seed/MNEME_OPERATOR_SEED or MNEME_KMS_MASTER_KEY_HEX"
            );
            CliErrorKind::Usage
        }
        other => CliErrorKind::Kernel(other),
    }
}

fn write_forget_proof(path: &Path, proof: &ForgetProof) -> Result<(), CliErrorKind> {
    let bytes = encode_forget_proof(proof).map_err(CliErrorKind::Kernel)?;
    std::fs::write(path, bytes).map_err(|_| CliErrorKind::Usage)
}

fn parse_seed_hex(hex_str: &str) -> Result<[u8; 32], CliErrorKind> {
    let bytes = hex::decode(hex_str).map_err(|_| CliErrorKind::Usage)?;
    if bytes.len() != 32 {
        return Err(CliErrorKind::Usage);
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn parse_i16_list(s: &str) -> Result<Vec<i16>, CliErrorKind> {
    if s.trim().is_empty() {
        return Ok(Vec::new());
    }
    s.split(',')
        .map(|part| part.trim().parse::<i16>().map_err(|_| CliErrorKind::Usage))
        .collect()
}

fn require_file_exists(path: &Path, label: &str) -> Result<(), CliErrorKind> {
    if !path.exists() {
        let mut msg = String::new();
        write!(msg, "{label} not found: {}", path.display()).ok();
        eprintln!("mneme: {msg}");
        return Err(CliErrorKind::Usage);
    }
    Ok(())
}

fn require_store_dir(store: &Path) -> Result<(), CliErrorKind> {
    if !store.exists() {
        let mut msg = String::new();
        write!(msg, "store path not found: {}", store.display()).ok();
        eprintln!("mneme: {msg}");
        return Err(CliErrorKind::Usage);
    }
    if !store.is_dir() {
        eprintln!("mneme: store path is not a directory: {}", store.display());
        return Err(CliErrorKind::Usage);
    }
    Ok(())
}

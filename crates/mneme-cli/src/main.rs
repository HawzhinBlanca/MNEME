//! `mneme` CLI — adoption-layer fail-closed gate (blueprint §14.2).

mod attest;
mod cert;
#[cfg(feature = "operator_tools")]
mod determinism;
mod generated_output;

use clap::{Parser, Subcommand, ValueEnum};
use mneme_cap::agent_cap;
use mneme_core::{
    DistanceMetric, Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Procedure,
    ProcedureAlgo, Query, RetrievalProofLevel, TrustTier,
};
use mneme_core::{ForgetProof, encode_forget_proof};
use mneme_crypto::{EnvelopeKeyVault, KeyPair, TrustConfig};
#[cfg(feature = "operator_tools")]
use mneme_root::{
    CheckpointLog, RootHistoryPeakConsistencyProof, RootHistoryPeakDigest,
    RootHistoryPeakFrontierProof, RootHistoryPeakInclusionProof, RootHistoryProofDirection,
    RootHistoryProofStep, StoredRoot,
};
use mneme_root::{RootHistoryPeak, RootHistoryPeakState};
use mneme_store::{Store, repair_store};
use mneme_verify::verify_store;
use serde::{Deserialize, Serialize};
#[cfg(feature = "operator_tools")]
use serde_json::{Value, json};
use std::fmt::Write as _;
#[cfg(feature = "operator_tools")]
use std::io::Write as _;
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
        /// External peak-state pin JSON; rejects rollback unless current history extends it.
        #[arg(long = "pin-peak-state")]
        pin_peak_state: Option<PathBuf>,
    },
    /// Operator audit: emit root-history/peak digest JSON for a store
    #[cfg(feature = "operator_tools")]
    Audit {
        store: Option<PathBuf>,
        /// Write the current compact peak state to PATH for later append-only verification.
        #[arg(long = "emit-peak-state")]
        emit_peak_state: Option<PathBuf>,
        /// Verify and atomically advance an operator peak-state pin outside STORE.
        #[arg(long = "pin-peak-state")]
        pin_peak_state: Option<PathBuf>,
        /// Verify that current HEAD extends a previously emitted peak state JSON.
        #[arg(long = "from-peak-state")]
        from_peak_state: Option<PathBuf>,
        /// Write a portable peak-consistency proof bundle; requires --from-peak-state.
        #[arg(long = "emit-peak-proof")]
        emit_peak_proof: Option<PathBuf>,
        /// Write a compact structural frontier proof bundle; requires --from-peak-state.
        #[arg(long = "emit-peak-frontier-proof")]
        emit_peak_frontier_proof: Option<PathBuf>,
        /// Checkpoint sequence for compact peak-inclusion proof export.
        #[arg(long = "checkpoint-sequence")]
        checkpoint_sequence: Option<u64>,
        /// Write a portable peak-inclusion proof bundle; requires --checkpoint-sequence.
        #[arg(long = "emit-peak-inclusion-proof")]
        emit_peak_inclusion_proof: Option<PathBuf>,
        /// Offline-verify a portable peak-consistency proof bundle; omit STORE.
        #[arg(long = "verify-peak-proof")]
        verify_peak_proof: Option<PathBuf>,
        /// Offline-verify a structural frontier proof bundle; omit STORE.
        #[arg(long = "verify-peak-frontier-proof")]
        verify_peak_frontier_proof: Option<PathBuf>,
        /// Offline-verify a portable peak-inclusion proof bundle; omit STORE.
        #[arg(long = "verify-peak-inclusion-proof")]
        verify_peak_inclusion_proof: Option<PathBuf>,
        /// Trusted operator public key hex for offline proof verification.
        #[arg(long = "operator-pubkey")]
        operator_pubkey: Option<String>,
    },
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
        #[arg(long = "ef-search", default_value_t = 64)]
        ef_search: u32,
        #[arg(long, default_value_t = 1)]
        k: u32,
    },
    /// Initialize a new store at PATH
    #[cfg(feature = "operator_tools")]
    Init { path: PathBuf },
    /// Determinism foundation gate (§17.7)
    #[cfg(feature = "operator_tools")]
    Determinism {
        #[command(subcommand)]
        command: DeterminismCommands,
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

#[cfg(feature = "operator_tools")]
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
}

impl From<ProofLevelArg> for RetrievalProofLevel {
    fn from(v: ProofLevelArg) -> Self {
        match v {
            ProofLevelArg::ExactDominance => RetrievalProofLevel::ExactDominance,
            ProofLevelArg::HnswAuditOnDemand => RetrievalProofLevel::HnswAuditOnDemand,
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
    VerifyFailed(MnemeError),
    Kernel(MnemeError),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakStateJson {
    schema: String,
    version: u16,
    sequence: u64,
    head_preimage_hash: String,
    peak_bag_root: String,
    peaks: Vec<PeakJson>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakJson {
    height: u32,
    hash: String,
}

#[cfg(feature = "operator_tools")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakDigestJson {
    sequence: u64,
    checkpoint_count: u64,
    head_preimage_hash: String,
    peak_count: u64,
    peak_bag_root: String,
}

#[cfg(feature = "operator_tools")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakConsistencyProofJson {
    from_sequence: u64,
    to_sequence: u64,
    from_peak_bag_root: String,
    to_peak_bag_root: String,
    appended_checkpoints_cbor: Vec<String>,
}

#[cfg(feature = "operator_tools")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakFrontierProofJson {
    from_sequence: u64,
    to_sequence: u64,
    from_peak_bag_root: String,
    to_peak_bag_root: String,
    appended_subtrees: Vec<PeakJson>,
}

#[cfg(feature = "operator_tools")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakProofStepJson {
    direction: String,
    sibling_hash: String,
}

#[cfg(feature = "operator_tools")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakInclusionProofJson {
    sequence: u64,
    checkpoint_count: u64,
    leaf_hash: String,
    peak_index: u64,
    peak_height: u32,
    peak_hash: String,
    peaks: Vec<PeakJson>,
    path: Vec<PeakProofStepJson>,
}

#[cfg(feature = "operator_tools")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakProofBundleJson {
    schema: String,
    operator_keys: Vec<String>,
    older: PeakStateJson,
    newer: PeakDigestJson,
    proof: PeakConsistencyProofJson,
}

#[cfg(feature = "operator_tools")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakFrontierProofBundleJson {
    schema: String,
    proof_kind: String,
    claim: String,
    signature_coverage: String,
    requires_external_pin: bool,
    signed_checkpoint_delta_required_for_signature_coverage: bool,
    older: PeakStateJson,
    newer: PeakDigestJson,
    proof: PeakFrontierProofJson,
}

#[cfg(feature = "operator_tools")]
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PeakInclusionProofBundleJson {
    schema: String,
    operator_keys: Vec<String>,
    digest: PeakDigestJson,
    checkpoint_cbor: String,
    proof: PeakInclusionProofJson,
}

#[cfg(feature = "operator_tools")]
struct AuditRequest<'a> {
    store: Option<&'a Path>,
    emit_peak_state: Option<&'a Path>,
    pin_peak_state: Option<&'a Path>,
    from_peak_state: Option<&'a Path>,
    emit_peak_proof: Option<&'a Path>,
    emit_peak_frontier_proof: Option<&'a Path>,
    checkpoint_sequence: Option<u64>,
    emit_peak_inclusion_proof: Option<&'a Path>,
    verify_peak_proof: Option<&'a Path>,
    verify_peak_frontier_proof: Option<&'a Path>,
    verify_peak_inclusion_proof: Option<&'a Path>,
    operator_pubkey: Option<&'a str>,
    seed_hex: Option<&'a str>,
    vault: VaultArg,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(kind) => {
            let (code, msg) = match kind {
                CliErrorKind::Usage => (2, "invalid usage".to_string()),
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
        #[cfg(feature = "operator_tools")]
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
        Commands::Verify {
            store,
            pin_root,
            pin_peak_state,
        } => {
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
            if let Some(pin_path) = pin_peak_state {
                verify_store_extends_peak_state_pin(&store, &pin_path, operator, cli.vault)?;
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
                validate_generated_output_path(&path)?;
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
        #[cfg(feature = "operator_tools")]
        Commands::Audit {
            store,
            emit_peak_state,
            pin_peak_state,
            from_peak_state,
            emit_peak_proof,
            emit_peak_frontier_proof,
            checkpoint_sequence,
            emit_peak_inclusion_proof,
            verify_peak_proof,
            verify_peak_frontier_proof,
            verify_peak_inclusion_proof,
            operator_pubkey,
        } => run_audit(AuditRequest {
            store: store.as_deref(),
            emit_peak_state: emit_peak_state.as_deref(),
            pin_peak_state: pin_peak_state.as_deref(),
            from_peak_state: from_peak_state.as_deref(),
            emit_peak_proof: emit_peak_proof.as_deref(),
            emit_peak_frontier_proof: emit_peak_frontier_proof.as_deref(),
            checkpoint_sequence,
            emit_peak_inclusion_proof: emit_peak_inclusion_proof.as_deref(),
            verify_peak_proof: verify_peak_proof.as_deref(),
            verify_peak_frontier_proof: verify_peak_frontier_proof.as_deref(),
            verify_peak_inclusion_proof: verify_peak_inclusion_proof.as_deref(),
            operator_pubkey: operator_pubkey.as_deref(),
            seed_hex: cli.operator_seed.as_deref(),
            vault: cli.vault,
        }),
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
            validate_generated_output_path(&out)?;
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
        Commands::VerifyCert { cert, ef_search, k } => {
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
            cert::run_verify_cert(&cert, &trust, &proc).map_err(CliErrorKind::VerifyFailed)?;
            println!("verify-cert ok: cognition certificate v1 valid offline");
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
        #[cfg(feature = "operator_tools")]
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

fn verify_store_extends_peak_state_pin(
    store: &Path,
    pin_path: &Path,
    operator: KeyPair,
    vault: VaultArg,
) -> Result<(), CliErrorKind> {
    ensure_peak_pin_outside_store(store, pin_path, false)?;
    let pinned = read_peak_state_json(pin_path)?;
    let mneme_store = open_store(store, operator, vault).map_err(|err| match err {
        CliErrorKind::Kernel(e) => CliErrorKind::VerifyFailed(e),
        other => other,
    })?;
    let peak_digest = mneme_store
        .root_history_peak_digest()
        .map_err(CliErrorKind::VerifyFailed)?;
    let proof = mneme_store
        .root_history_peak_consistency_proof(&pinned)
        .map_err(CliErrorKind::VerifyFailed)?;
    mneme_root::verify_root_history_peak_consistency(
        &mneme_store.trust().operator_keys,
        &pinned,
        &peak_digest,
        &proof,
    )
    .map_err(CliErrorKind::VerifyFailed)
}

#[cfg(feature = "operator_tools")]
fn run_audit(request: AuditRequest<'_>) -> Result<(), CliErrorKind> {
    if let Some(proof_path) = request.verify_peak_proof {
        if request.store.is_some()
            || request.emit_peak_state.is_some()
            || request.pin_peak_state.is_some()
            || request.from_peak_state.is_some()
            || request.emit_peak_proof.is_some()
            || request.emit_peak_frontier_proof.is_some()
            || request.checkpoint_sequence.is_some()
            || request.emit_peak_inclusion_proof.is_some()
            || request.verify_peak_frontier_proof.is_some()
            || request.verify_peak_inclusion_proof.is_some()
        {
            eprintln!("mneme: --verify-peak-proof is offline; omit STORE and live audit flags");
            return Err(CliErrorKind::Usage);
        }
        return run_verify_peak_proof(proof_path, request.operator_pubkey, request.seed_hex);
    }
    if let Some(proof_path) = request.verify_peak_frontier_proof {
        if request.store.is_some()
            || request.emit_peak_state.is_some()
            || request.pin_peak_state.is_some()
            || request.from_peak_state.is_some()
            || request.emit_peak_proof.is_some()
            || request.emit_peak_frontier_proof.is_some()
            || request.checkpoint_sequence.is_some()
            || request.emit_peak_inclusion_proof.is_some()
            || request.verify_peak_inclusion_proof.is_some()
        {
            eprintln!(
                "mneme: --verify-peak-frontier-proof is offline; omit STORE and live audit flags"
            );
            return Err(CliErrorKind::Usage);
        }
        return run_verify_peak_frontier_proof(
            proof_path,
            request.operator_pubkey,
            request.seed_hex,
        );
    }
    if let Some(proof_path) = request.verify_peak_inclusion_proof {
        if request.store.is_some()
            || request.emit_peak_state.is_some()
            || request.pin_peak_state.is_some()
            || request.from_peak_state.is_some()
            || request.emit_peak_proof.is_some()
            || request.emit_peak_frontier_proof.is_some()
            || request.checkpoint_sequence.is_some()
            || request.emit_peak_inclusion_proof.is_some()
        {
            eprintln!(
                "mneme: --verify-peak-inclusion-proof is offline; omit STORE and live audit flags"
            );
            return Err(CliErrorKind::Usage);
        }
        return run_verify_peak_inclusion_proof(
            proof_path,
            request.operator_pubkey,
            request.seed_hex,
        );
    }
    let store = request.store.ok_or_else(|| {
        eprintln!("mneme: audit requires STORE unless offline proof verification is used");
        CliErrorKind::Usage
    })?;
    if request.emit_peak_proof.is_some() && request.from_peak_state.is_none() {
        eprintln!("mneme: --emit-peak-proof requires --from-peak-state");
        return Err(CliErrorKind::Usage);
    }
    if request.emit_peak_frontier_proof.is_some() && request.from_peak_state.is_none() {
        eprintln!("mneme: --emit-peak-frontier-proof requires --from-peak-state");
        return Err(CliErrorKind::Usage);
    }
    if request.emit_peak_inclusion_proof.is_some() && request.checkpoint_sequence.is_none() {
        eprintln!("mneme: --emit-peak-inclusion-proof requires --checkpoint-sequence");
        return Err(CliErrorKind::Usage);
    }
    require_store_dir(store)?;
    let operator = load_or_generate_operator(store, request.seed_hex)?;
    if let Some(operator_pubkey) = request.operator_pubkey {
        let expected = parse_seed_hex(operator_pubkey)?;
        if operator.public_key_bytes() != expected {
            return Err(CliErrorKind::VerifyFailed(MnemeError::RootSigInvalid));
        }
    }
    let trust = TrustConfig::new(operator.public_key_bytes());
    let verify_report = verify_store(store, &trust).map_err(CliErrorKind::VerifyFailed)?;
    let mneme_store = open_store(store, operator, request.vault).map_err(|err| match err {
        CliErrorKind::Kernel(e) => CliErrorKind::VerifyFailed(e),
        other => other,
    })?;
    let root_history = mneme_store
        .root_history_digest()
        .map_err(CliErrorKind::VerifyFailed)?;
    let peak_state = mneme_store
        .root_history_peak_state()
        .map_err(CliErrorKind::VerifyFailed)?;
    let peak_digest = mneme_store
        .root_history_peak_digest()
        .map_err(CliErrorKind::VerifyFailed)?;

    if let Some(path) = request.emit_peak_state {
        write_peak_state_json(path, &peak_state)?;
    }

    let (peak_consistency, peak_frontier) = if let Some(path) = request.from_peak_state {
        let older = read_peak_state_json(path)?;
        let proof = mneme_store
            .root_history_peak_consistency_proof(&older)
            .map_err(CliErrorKind::VerifyFailed)?;
        mneme_root::verify_root_history_peak_consistency(
            &mneme_store.trust().operator_keys,
            &older,
            &peak_digest,
            &proof,
        )
        .map_err(CliErrorKind::VerifyFailed)?;
        if let Some(path) = request.emit_peak_proof {
            write_peak_proof_bundle(
                path,
                &mneme_store.trust().operator_keys,
                &older,
                &peak_digest,
                &proof,
            )?;
        }
        let frontier = mneme_store
            .root_history_peak_frontier_proof(&older)
            .map_err(CliErrorKind::VerifyFailed)?;
        mneme_root::verify_root_history_peak_frontier(&older, &peak_digest, &frontier)
            .map_err(CliErrorKind::VerifyFailed)?;
        if let Some(path) = request.emit_peak_frontier_proof {
            write_peak_frontier_proof_bundle(path, &older, &peak_digest, &frontier)?;
        }
        let consistency_report = json!({
            "verified": true,
            "from_sequence": proof.from_sequence,
            "to_sequence": proof.to_sequence,
            "from_peak_bag_root": hex::encode(proof.from_peak_bag_root),
            "to_peak_bag_root": hex::encode(proof.to_peak_bag_root),
            "appended_checkpoint_count": proof.appended_checkpoints.len(),
            "proof_emitted": request.emit_peak_proof.map(|path| path.display().to_string()),
        });
        let frontier_report = json!({
            "verified": true,
            "proof_kind": "structural_frontier.v1",
            "claim": "structural_frontier_only",
            "signature_coverage": "none_for_appended_subtrees",
            "requires_external_pin": true,
            "signed_checkpoint_delta_required_for_signature_coverage": true,
            "from_sequence": frontier.from_sequence,
            "to_sequence": frontier.to_sequence,
            "from_peak_bag_root": hex::encode(frontier.from_peak_bag_root),
            "to_peak_bag_root": hex::encode(frontier.to_peak_bag_root),
            "appended_subtree_count": frontier.appended_subtrees.len(),
            "proof_emitted": request.emit_peak_frontier_proof.map(|path| path.display().to_string()),
        });
        (Some(consistency_report), Some(frontier_report))
    } else {
        (None, None)
    };

    let peak_inclusion = if let Some(sequence) = request.checkpoint_sequence {
        let proof = mneme_store
            .root_history_peak_inclusion_proof(sequence)
            .map_err(CliErrorKind::VerifyFailed)?;
        let checkpoint =
            CheckpointLog::read_checkpoint(store, sequence).map_err(CliErrorKind::VerifyFailed)?;
        mneme_root::verify_root_history_peak_inclusion(
            &mneme_store.trust().operator_keys,
            &peak_digest,
            &checkpoint,
            &proof,
        )
        .map_err(CliErrorKind::VerifyFailed)?;
        if let Some(path) = request.emit_peak_inclusion_proof {
            write_peak_inclusion_proof_bundle(
                path,
                &mneme_store.trust().operator_keys,
                &peak_digest,
                &checkpoint,
                &proof,
            )?;
        }
        Some(json!({
            "verified": true,
            "sequence": proof.sequence,
            "checkpoint_count": proof.checkpoint_count,
            "peak_index": proof.peak_index,
            "peak_height": proof.peak_height,
            "path_len": proof.path.len(),
            "proof_emitted": request.emit_peak_inclusion_proof.map(|path| path.display().to_string()),
        }))
    } else {
        None
    };

    let peak_pin = if let Some(path) = request.pin_peak_state {
        Some(update_peak_state_pin(
            store,
            path,
            &mneme_store,
            &peak_state,
            &peak_digest,
        )?)
    } else {
        None
    };

    let mut report = json!({
        "schema": "mneme.audit.root_history.v1",
        "store": store.display().to_string(),
        "verify_store": {
            "verified": true,
            "root_sequence": verify_report.root.sequence,
            "object_count": verify_report.object_count,
        },
        "root_history": {
            "sequence": root_history.sequence,
            "checkpoint_count": root_history.checkpoint_count,
            "head_preimage_hash": hex::encode(root_history.head_preimage_hash),
            "accumulator_root": hex::encode(root_history.accumulator_root),
        },
        "peak_digest": {
            "sequence": peak_digest.sequence,
            "checkpoint_count": peak_digest.checkpoint_count,
            "head_preimage_hash": hex::encode(peak_digest.head_preimage_hash),
            "peak_count": peak_digest.peak_count,
            "peak_bag_root": hex::encode(peak_digest.peak_bag_root),
        },
        "peak_state": peak_state_json_value(&peak_state),
    });
    if let Some(peak_consistency) = peak_consistency {
        report["peak_consistency"] = peak_consistency;
    }
    if let Some(peak_frontier) = peak_frontier {
        report["peak_frontier"] = peak_frontier;
    }
    if let Some(peak_inclusion) = peak_inclusion {
        report["peak_inclusion"] = peak_inclusion;
    }
    if let Some(peak_pin) = peak_pin {
        report["peak_pin"] = peak_pin;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&report).map_err(|_| CliErrorKind::Usage)?
    );
    Ok(())
}

#[cfg(feature = "operator_tools")]
fn update_peak_state_pin(
    store: &Path,
    path: &Path,
    mneme_store: &Store,
    peak_state: &RootHistoryPeakState,
    peak_digest: &RootHistoryPeakDigest,
) -> Result<Value, CliErrorKind> {
    ensure_peak_pin_outside_store(store, path, true)?;
    let existed = path.exists();
    let report = if existed {
        let older = read_peak_state_json(path)?;
        let proof = mneme_store
            .root_history_peak_consistency_proof(&older)
            .map_err(CliErrorKind::VerifyFailed)?;
        mneme_root::verify_root_history_peak_consistency(
            &mneme_store.trust().operator_keys,
            &older,
            peak_digest,
            &proof,
        )
        .map_err(CliErrorKind::VerifyFailed)?;
        let status = if older.sequence == peak_state.sequence {
            "unchanged"
        } else {
            "advanced"
        };
        json!({
            "verified": true,
            "status": status,
            "path": path.display().to_string(),
            "pin_schema": "mneme.audit.peak_state.v1",
            "proof_kind": "signed_delta_consistency.v1",
            "from_sequence": older.sequence,
            "to_sequence": peak_state.sequence,
            "from_peak_bag_root": hex::encode(older.peak_bag_root),
            "to_peak_bag_root": hex::encode(peak_state.peak_bag_root),
            "appended_checkpoint_count": proof.appended_checkpoints.len(),
            "snapshot_rollback_resistance_requires_pin_outside_store": true,
            "same_host_pin_file_can_be_rolled_back_with_store": true,
        })
    } else {
        json!({
            "verified": true,
            "status": "created",
            "path": path.display().to_string(),
            "pin_schema": "mneme.audit.peak_state.v1",
            "proof_kind": "initial_peak_state_pin.v1",
            "from_sequence": Value::Null,
            "to_sequence": peak_state.sequence,
            "from_peak_bag_root": Value::Null,
            "to_peak_bag_root": hex::encode(peak_state.peak_bag_root),
            "appended_checkpoint_count": Value::Null,
            "snapshot_rollback_resistance_requires_pin_outside_store": true,
            "same_host_pin_file_can_be_rolled_back_with_store": true,
        })
    };
    write_peak_state_json_atomic(path, peak_state)?;
    Ok(report)
}

fn ensure_peak_pin_outside_store(
    store: &Path,
    path: &Path,
    create_parent: bool,
) -> Result<(), CliErrorKind> {
    let store = std::fs::canonicalize(store).map_err(|_| CliErrorKind::Usage)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if create_parent {
        ensure_peak_state_parent_dir(parent)?;
    } else {
        reject_peak_state_parent_alias(parent)?;
    }
    if let Some(metadata) = existing_peak_pin_metadata(path)? {
        reject_existing_peak_pin_if_aliased(path, &metadata)?;
        let target = std::fs::canonicalize(path).map_err(|_| CliErrorKind::Usage)?;
        if target.starts_with(&store) {
            eprintln!("mneme: --pin-peak-state must reference a path outside STORE");
            return Err(CliErrorKind::Usage);
        }
    }
    let parent = std::fs::canonicalize(parent).map_err(|_| CliErrorKind::Usage)?;
    if parent.starts_with(&store) {
        eprintln!("mneme: --pin-peak-state must reference a path outside STORE");
        return Err(CliErrorKind::Usage);
    }
    Ok(())
}

fn ensure_peak_state_parent_dir(parent: &Path) -> Result<(), CliErrorKind> {
    if parent.as_os_str().is_empty() {
        return Ok(());
    }
    reject_peak_state_parent_alias(parent)?;
    std::fs::create_dir_all(parent).map_err(|_| CliErrorKind::Usage)?;
    reject_peak_state_parent_alias(parent)
}

fn reject_peak_state_parent_alias(parent: &Path) -> Result<(), CliErrorKind> {
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                eprintln!(
                    "mneme: --pin-peak-state parent must be a directory, not a symlink: {}",
                    parent.display()
                );
                return Err(CliErrorKind::Usage);
            }
            if !file_type.is_dir() {
                eprintln!(
                    "mneme: --pin-peak-state parent must be a directory: {}",
                    parent.display()
                );
                return Err(CliErrorKind::Usage);
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(CliErrorKind::Usage),
    }
}

fn existing_peak_pin_metadata(path: &Path) -> Result<Option<std::fs::Metadata>, CliErrorKind> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(CliErrorKind::Usage),
    }
}

fn reject_existing_peak_pin_if_aliased(
    path: &Path,
    metadata: &std::fs::Metadata,
) -> Result<(), CliErrorKind> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        eprintln!(
            "mneme: --pin-peak-state must reference a regular file, not a symlink: {}",
            path.display()
        );
        return Err(CliErrorKind::Usage);
    }
    if !file_type.is_file() {
        eprintln!(
            "mneme: --pin-peak-state must reference a regular file: {}",
            path.display()
        );
        return Err(CliErrorKind::Usage);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            eprintln!(
                "mneme: --pin-peak-state must not be hard-linked: {}",
                path.display()
            );
            return Err(CliErrorKind::Usage);
        }
    }
    Ok(())
}

#[cfg(feature = "operator_tools")]
fn run_verify_peak_proof(
    proof_path: &Path,
    operator_pubkey: Option<&str>,
    seed_hex: Option<&str>,
) -> Result<(), CliErrorKind> {
    let operator_keys = trusted_operator_keys(operator_pubkey, seed_hex)?;
    let bundle = read_peak_proof_bundle(proof_path)?;
    let older = peak_state_from_json(bundle.older)?;
    let newer = peak_digest_from_json(bundle.newer)?;
    let proof = peak_consistency_proof_from_json(bundle.proof)?;
    mneme_root::verify_root_history_peak_consistency(&operator_keys, &older, &newer, &proof)
        .map_err(CliErrorKind::VerifyFailed)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "mneme.audit.peak_proof_verification.v1",
            "verified": true,
            "from_sequence": proof.from_sequence,
            "to_sequence": proof.to_sequence,
            "trusted_operator_keys": operator_keys.iter().map(hex::encode).collect::<Vec<_>>(),
            "appended_checkpoint_count": proof.appended_checkpoints.len(),
        }))
        .map_err(|_| CliErrorKind::Usage)?
    );
    Ok(())
}

#[cfg(feature = "operator_tools")]
fn run_verify_peak_frontier_proof(
    proof_path: &Path,
    operator_pubkey: Option<&str>,
    seed_hex: Option<&str>,
) -> Result<(), CliErrorKind> {
    if operator_pubkey.is_some() || seed_hex.is_some() {
        eprintln!(
            "mneme: --verify-peak-frontier-proof is structural-only; operator keys are not used"
        );
        return Err(CliErrorKind::Usage);
    }
    let bundle = read_peak_frontier_proof_bundle(proof_path)?;
    let older = peak_state_from_json(bundle.older)?;
    let newer = peak_digest_from_json(bundle.newer)?;
    let proof = peak_frontier_proof_from_json(bundle.proof)?;
    mneme_root::verify_root_history_peak_frontier(&older, &newer, &proof)
        .map_err(CliErrorKind::VerifyFailed)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "mneme.audit.peak_frontier_proof_verification.v1",
            "verified": true,
            "proof_kind": "structural_frontier.v1",
            "claim": "structural_frontier_only",
            "signature_coverage": "none_for_appended_subtrees",
            "requires_external_pin": true,
            "signed_checkpoint_delta_required_for_signature_coverage": true,
            "from_sequence": proof.from_sequence,
            "to_sequence": proof.to_sequence,
            "appended_subtree_count": proof.appended_subtrees.len(),
        }))
        .map_err(|_| CliErrorKind::Usage)?
    );
    Ok(())
}

#[cfg(feature = "operator_tools")]
fn run_verify_peak_inclusion_proof(
    proof_path: &Path,
    operator_pubkey: Option<&str>,
    seed_hex: Option<&str>,
) -> Result<(), CliErrorKind> {
    let operator_keys = trusted_operator_keys(operator_pubkey, seed_hex)?;
    let bundle = read_peak_inclusion_proof_bundle(proof_path)?;
    let digest = peak_digest_from_json(bundle.digest)?;
    let checkpoint_bytes = hex::decode(bundle.checkpoint_cbor).map_err(|_| CliErrorKind::Usage)?;
    let checkpoint =
        StoredRoot::from_bytes(&checkpoint_bytes).map_err(CliErrorKind::VerifyFailed)?;
    let proof = peak_inclusion_proof_from_json(bundle.proof)?;
    mneme_root::verify_root_history_peak_inclusion(&operator_keys, &digest, &checkpoint, &proof)
        .map_err(CliErrorKind::VerifyFailed)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "mneme.audit.peak_inclusion_proof_verification.v1",
            "verified": true,
            "sequence": proof.sequence,
            "checkpoint_count": proof.checkpoint_count,
            "trusted_operator_keys": operator_keys.iter().map(hex::encode).collect::<Vec<_>>(),
            "path_len": proof.path.len(),
        }))
        .map_err(|_| CliErrorKind::Usage)?
    );
    Ok(())
}

#[cfg(feature = "operator_tools")]
fn write_peak_state_json(path: &Path, state: &RootHistoryPeakState) -> Result<(), CliErrorKind> {
    let data =
        serde_json::to_vec_pretty(&peak_state_to_json(state)).map_err(|_| CliErrorKind::Usage)?;
    write_generated_output_file(path, &data)
}

#[cfg(feature = "operator_tools")]
fn write_peak_state_json_atomic(
    path: &Path,
    state: &RootHistoryPeakState,
) -> Result<(), CliErrorKind> {
    let data =
        serde_json::to_vec_pretty(&peak_state_to_json(state)).map_err(|_| CliErrorKind::Usage)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_peak_state_parent_dir(parent)?;
    let file_name = path.file_name().ok_or(CliErrorKind::Usage)?;
    let (tmp_path, mut file) = create_peak_state_tmp_file(parent, file_name)?;
    let result = (|| {
        file.write_all(&data).map_err(|_| CliErrorKind::Usage)?;
        file.sync_all().map_err(|_| CliErrorKind::Usage)?;
        let metadata = file.metadata().map_err(|_| CliErrorKind::Usage)?;
        reject_existing_peak_pin_if_aliased(&tmp_path, &metadata)?;
        std::fs::rename(&tmp_path, path).map_err(|_| CliErrorKind::Usage)?;
        sync_peak_state_parent_dir(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

#[cfg(feature = "operator_tools")]
fn sync_peak_state_parent_dir(parent: &Path) -> Result<(), CliErrorKind> {
    #[cfg(unix)]
    {
        if parent.as_os_str().is_empty() {
            return Ok(());
        }
        reject_peak_state_parent_alias(parent)?;
        let dir = std::fs::File::open(parent).map_err(|_| CliErrorKind::Usage)?;
        dir.sync_all().map_err(|_| CliErrorKind::Usage)
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
        Ok(())
    }
}

#[cfg(feature = "operator_tools")]
fn create_peak_state_tmp_file(
    parent: &Path,
    file_name: &std::ffi::OsStr,
) -> Result<(PathBuf, std::fs::File), CliErrorKind> {
    create_peak_state_tmp_file_from_nonces(parent, file_name, rand::random::<u64>)
}

#[cfg(feature = "operator_tools")]
fn create_peak_state_tmp_file_from_nonces(
    parent: &Path,
    file_name: &std::ffi::OsStr,
    mut next_nonce: impl FnMut() -> u64,
) -> Result<(PathBuf, std::fs::File), CliErrorKind> {
    for _ in 0..16 {
        let mut tmp_name = std::ffi::OsString::from(".");
        tmp_name.push(file_name);
        tmp_name.push(format!(".{}.{}.tmp", std::process::id(), next_nonce()));
        let tmp_path = parent.join(tmp_name);
        let mut open = std::fs::OpenOptions::new();
        open.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open.custom_flags(libc::O_NOFOLLOW);
        }
        match open.open(&tmp_path) {
            Ok(file) => {
                let metadata = file.metadata().map_err(|_| CliErrorKind::Usage)?;
                reject_existing_peak_pin_if_aliased(&tmp_path, &metadata)?;
                return Ok((tmp_path, file));
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(CliErrorKind::Usage),
        }
    }
    Err(CliErrorKind::Usage)
}

#[cfg(all(test, feature = "operator_tools", unix))]
mod tests {
    use super::*;

    fn sample_peak_state() -> RootHistoryPeakState {
        RootHistoryPeakState {
            version: 1,
            sequence: 1,
            head_preimage_hash: [1_u8; 32],
            peaks: vec![RootHistoryPeak {
                height: 0,
                hash: [2_u8; 32],
            }],
            peak_bag_root: [3_u8; 32],
        }
    }

    #[test]
    fn peak_state_tmp_file_skips_preexisting_symlink_without_truncating_target() {
        let dir = tempfile::tempdir().expect("tempdir");
        let parent = dir.path();
        let file_name = std::ffi::OsStr::new("pin.json");
        let victim = parent.join("victim.json");
        std::fs::write(&victim, b"victim").expect("victim fixture");

        let first_tmp = parent.join(format!(".pin.json.{}.{}.tmp", std::process::id(), 7_u64));
        std::os::unix::fs::symlink(&victim, &first_tmp).expect("symlink tmp fixture");

        let mut call_count = 0_u8;
        let (second_tmp, file) = create_peak_state_tmp_file_from_nonces(parent, file_name, || {
            call_count += 1;
            if call_count == 1 { 7 } else { 8 }
        })
        .expect("second nonce should create a fresh tmp file");
        drop(file);

        assert_ne!(second_tmp, first_tmp);
        assert!(second_tmp.exists());
        assert_eq!(std::fs::read(&victim).expect("victim read"), b"victim");
        assert!(
            std::fs::symlink_metadata(&first_tmp)
                .expect("first tmp symlink")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn peak_state_atomic_write_rejects_symlinked_parent_without_writing_external_pin() {
        let dir = tempfile::tempdir().expect("tempdir");
        let external_parent = dir.path().join("external");
        let linked_parent = dir.path().join("linked");
        std::fs::create_dir(&external_parent).expect("external parent fixture");
        std::os::unix::fs::symlink(&external_parent, &linked_parent)
            .expect("linked parent fixture");

        let err =
            write_peak_state_json_atomic(&linked_parent.join("pin.json"), &sample_peak_state())
                .expect_err("symlinked pin parent must fail closed");

        assert_eq!(err, CliErrorKind::Usage);
        assert!(
            std::fs::read_dir(&external_parent)
                .expect("external parent read")
                .next()
                .is_none()
        );
        assert!(
            std::fs::symlink_metadata(&linked_parent)
                .expect("linked parent")
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn peak_pin_preflight_rejects_existing_pin_behind_symlinked_parent() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = dir.path().join("store");
        let external_parent = dir.path().join("external");
        let linked_parent = dir.path().join("linked");
        std::fs::create_dir(&store).expect("store fixture");
        std::fs::create_dir(&external_parent).expect("external parent fixture");
        write_peak_state_json_atomic(&external_parent.join("pin.json"), &sample_peak_state())
            .expect("external pin fixture");
        std::os::unix::fs::symlink(&external_parent, &linked_parent)
            .expect("linked parent fixture");

        let err = ensure_peak_pin_outside_store(&store, &linked_parent.join("pin.json"), false)
            .expect_err("existing pin behind symlinked parent must fail closed");

        assert_eq!(err, CliErrorKind::Usage);
    }
}

fn read_peak_state_json(path: &Path) -> Result<RootHistoryPeakState, CliErrorKind> {
    require_file_exists(path, "peak state")?;
    let bytes = std::fs::read(path).map_err(|_| CliErrorKind::Usage)?;
    let parsed: PeakStateJson = serde_json::from_slice(&bytes).map_err(|_| CliErrorKind::Usage)?;
    peak_state_from_json(parsed)
}

#[cfg(feature = "operator_tools")]
fn peak_state_json_value(state: &RootHistoryPeakState) -> Value {
    serde_json::to_value(peak_state_to_json(state)).unwrap_or(Value::Null)
}

#[cfg(feature = "operator_tools")]
fn peak_state_to_json(state: &RootHistoryPeakState) -> PeakStateJson {
    PeakStateJson {
        schema: "mneme.audit.peak_state.v1".into(),
        version: state.version,
        sequence: state.sequence,
        head_preimage_hash: hex::encode(state.head_preimage_hash),
        peak_bag_root: hex::encode(state.peak_bag_root),
        peaks: state
            .peaks
            .iter()
            .map(|peak| PeakJson {
                height: peak.height,
                hash: hex::encode(peak.hash),
            })
            .collect(),
    }
}

fn peak_state_from_json(parsed: PeakStateJson) -> Result<RootHistoryPeakState, CliErrorKind> {
    if parsed.schema != "mneme.audit.peak_state.v1" {
        return Err(CliErrorKind::Usage);
    }
    Ok(RootHistoryPeakState {
        version: parsed.version,
        sequence: parsed.sequence,
        head_preimage_hash: parse_seed_hex(&parsed.head_preimage_hash)?,
        peak_bag_root: parse_seed_hex(&parsed.peak_bag_root)?,
        peaks: parsed
            .peaks
            .into_iter()
            .map(|peak| {
                Ok(RootHistoryPeak {
                    height: peak.height,
                    hash: parse_seed_hex(&peak.hash)?,
                })
            })
            .collect::<Result<Vec<_>, CliErrorKind>>()?,
    })
}

#[cfg(feature = "operator_tools")]
fn peak_digest_to_json(digest: &RootHistoryPeakDigest) -> PeakDigestJson {
    PeakDigestJson {
        sequence: digest.sequence,
        checkpoint_count: digest.checkpoint_count,
        head_preimage_hash: hex::encode(digest.head_preimage_hash),
        peak_count: digest.peak_count,
        peak_bag_root: hex::encode(digest.peak_bag_root),
    }
}

#[cfg(feature = "operator_tools")]
fn peak_digest_from_json(parsed: PeakDigestJson) -> Result<RootHistoryPeakDigest, CliErrorKind> {
    Ok(RootHistoryPeakDigest {
        sequence: parsed.sequence,
        checkpoint_count: parsed.checkpoint_count,
        head_preimage_hash: parse_seed_hex(&parsed.head_preimage_hash)?,
        peak_count: parsed.peak_count,
        peak_bag_root: parse_seed_hex(&parsed.peak_bag_root)?,
    })
}

#[cfg(feature = "operator_tools")]
fn peak_consistency_proof_to_json(
    proof: &RootHistoryPeakConsistencyProof,
) -> Result<PeakConsistencyProofJson, CliErrorKind> {
    Ok(PeakConsistencyProofJson {
        from_sequence: proof.from_sequence,
        to_sequence: proof.to_sequence,
        from_peak_bag_root: hex::encode(proof.from_peak_bag_root),
        to_peak_bag_root: hex::encode(proof.to_peak_bag_root),
        appended_checkpoints_cbor: proof
            .appended_checkpoints
            .iter()
            .map(|checkpoint| {
                checkpoint
                    .to_bytes()
                    .map(hex::encode)
                    .map_err(CliErrorKind::Kernel)
            })
            .collect::<Result<Vec<_>, CliErrorKind>>()?,
    })
}

#[cfg(feature = "operator_tools")]
fn peak_consistency_proof_from_json(
    parsed: PeakConsistencyProofJson,
) -> Result<RootHistoryPeakConsistencyProof, CliErrorKind> {
    Ok(RootHistoryPeakConsistencyProof {
        from_sequence: parsed.from_sequence,
        to_sequence: parsed.to_sequence,
        from_peak_bag_root: parse_seed_hex(&parsed.from_peak_bag_root)?,
        to_peak_bag_root: parse_seed_hex(&parsed.to_peak_bag_root)?,
        appended_checkpoints: parsed
            .appended_checkpoints_cbor
            .into_iter()
            .map(|checkpoint_hex| {
                let bytes = hex::decode(checkpoint_hex).map_err(|_| CliErrorKind::Usage)?;
                StoredRoot::from_bytes(&bytes).map_err(CliErrorKind::VerifyFailed)
            })
            .collect::<Result<Vec<_>, CliErrorKind>>()?,
    })
}

#[cfg(feature = "operator_tools")]
fn peak_frontier_proof_to_json(proof: &RootHistoryPeakFrontierProof) -> PeakFrontierProofJson {
    PeakFrontierProofJson {
        from_sequence: proof.from_sequence,
        to_sequence: proof.to_sequence,
        from_peak_bag_root: hex::encode(proof.from_peak_bag_root),
        to_peak_bag_root: hex::encode(proof.to_peak_bag_root),
        appended_subtrees: proof
            .appended_subtrees
            .iter()
            .map(|peak| PeakJson {
                height: peak.height,
                hash: hex::encode(peak.hash),
            })
            .collect(),
    }
}

#[cfg(feature = "operator_tools")]
fn peak_frontier_proof_from_json(
    parsed: PeakFrontierProofJson,
) -> Result<RootHistoryPeakFrontierProof, CliErrorKind> {
    Ok(RootHistoryPeakFrontierProof {
        from_sequence: parsed.from_sequence,
        to_sequence: parsed.to_sequence,
        from_peak_bag_root: parse_seed_hex(&parsed.from_peak_bag_root)?,
        to_peak_bag_root: parse_seed_hex(&parsed.to_peak_bag_root)?,
        appended_subtrees: parsed
            .appended_subtrees
            .into_iter()
            .map(|peak| {
                Ok(RootHistoryPeak {
                    height: peak.height,
                    hash: parse_seed_hex(&peak.hash)?,
                })
            })
            .collect::<Result<Vec<_>, CliErrorKind>>()?,
    })
}

#[cfg(feature = "operator_tools")]
fn peak_inclusion_proof_to_json(proof: &RootHistoryPeakInclusionProof) -> PeakInclusionProofJson {
    PeakInclusionProofJson {
        sequence: proof.sequence,
        checkpoint_count: proof.checkpoint_count,
        leaf_hash: hex::encode(proof.leaf_hash),
        peak_index: proof.peak_index,
        peak_height: proof.peak_height,
        peak_hash: hex::encode(proof.peak_hash),
        peaks: proof
            .peaks
            .iter()
            .map(|peak| PeakJson {
                height: peak.height,
                hash: hex::encode(peak.hash),
            })
            .collect(),
        path: proof.path.iter().map(proof_step_to_json).collect(),
    }
}

#[cfg(feature = "operator_tools")]
fn peak_inclusion_proof_from_json(
    parsed: PeakInclusionProofJson,
) -> Result<RootHistoryPeakInclusionProof, CliErrorKind> {
    Ok(RootHistoryPeakInclusionProof {
        sequence: parsed.sequence,
        checkpoint_count: parsed.checkpoint_count,
        leaf_hash: parse_seed_hex(&parsed.leaf_hash)?,
        peak_index: parsed.peak_index,
        peak_height: parsed.peak_height,
        peak_hash: parse_seed_hex(&parsed.peak_hash)?,
        peaks: parsed
            .peaks
            .into_iter()
            .map(|peak| {
                Ok(RootHistoryPeak {
                    height: peak.height,
                    hash: parse_seed_hex(&peak.hash)?,
                })
            })
            .collect::<Result<Vec<_>, CliErrorKind>>()?,
        path: parsed
            .path
            .into_iter()
            .map(proof_step_from_json)
            .collect::<Result<Vec<_>, CliErrorKind>>()?,
    })
}

#[cfg(feature = "operator_tools")]
fn proof_step_to_json(step: &RootHistoryProofStep) -> PeakProofStepJson {
    let direction = match step.direction {
        RootHistoryProofDirection::Left => "left",
        RootHistoryProofDirection::Right => "right",
    };
    PeakProofStepJson {
        direction: direction.into(),
        sibling_hash: hex::encode(step.sibling_hash),
    }
}

#[cfg(feature = "operator_tools")]
fn proof_step_from_json(parsed: PeakProofStepJson) -> Result<RootHistoryProofStep, CliErrorKind> {
    let direction = match parsed.direction.as_str() {
        "left" => RootHistoryProofDirection::Left,
        "right" => RootHistoryProofDirection::Right,
        _ => return Err(CliErrorKind::Usage),
    };
    Ok(RootHistoryProofStep {
        direction,
        sibling_hash: parse_seed_hex(&parsed.sibling_hash)?,
    })
}

#[cfg(feature = "operator_tools")]
fn write_peak_proof_bundle(
    path: &Path,
    operator_keys: &[[u8; 32]],
    older: &RootHistoryPeakState,
    newer: &RootHistoryPeakDigest,
    proof: &RootHistoryPeakConsistencyProof,
) -> Result<(), CliErrorKind> {
    let bundle = PeakProofBundleJson {
        schema: "mneme.audit.peak_consistency_proof.v1".into(),
        operator_keys: operator_keys.iter().map(hex::encode).collect(),
        older: peak_state_to_json(older),
        newer: peak_digest_to_json(newer),
        proof: peak_consistency_proof_to_json(proof)?,
    };
    let data = serde_json::to_vec_pretty(&bundle).map_err(|_| CliErrorKind::Usage)?;
    write_generated_output_file(path, &data)
}

#[cfg(feature = "operator_tools")]
fn write_peak_inclusion_proof_bundle(
    path: &Path,
    operator_keys: &[[u8; 32]],
    digest: &RootHistoryPeakDigest,
    checkpoint: &StoredRoot,
    proof: &RootHistoryPeakInclusionProof,
) -> Result<(), CliErrorKind> {
    let bundle = PeakInclusionProofBundleJson {
        schema: "mneme.audit.peak_inclusion_proof.v1".into(),
        operator_keys: operator_keys.iter().map(hex::encode).collect(),
        digest: peak_digest_to_json(digest),
        checkpoint_cbor: checkpoint
            .to_bytes()
            .map(hex::encode)
            .map_err(CliErrorKind::Kernel)?,
        proof: peak_inclusion_proof_to_json(proof),
    };
    let data = serde_json::to_vec_pretty(&bundle).map_err(|_| CliErrorKind::Usage)?;
    write_generated_output_file(path, &data)
}

#[cfg(feature = "operator_tools")]
fn write_peak_frontier_proof_bundle(
    path: &Path,
    older: &RootHistoryPeakState,
    newer: &RootHistoryPeakDigest,
    proof: &RootHistoryPeakFrontierProof,
) -> Result<(), CliErrorKind> {
    let bundle = PeakFrontierProofBundleJson {
        schema: "mneme.audit.peak_frontier_proof.v1".into(),
        proof_kind: "structural_frontier.v1".into(),
        claim: "structural_frontier_only".into(),
        signature_coverage: "none_for_appended_subtrees".into(),
        requires_external_pin: true,
        signed_checkpoint_delta_required_for_signature_coverage: true,
        older: peak_state_to_json(older),
        newer: peak_digest_to_json(newer),
        proof: peak_frontier_proof_to_json(proof),
    };
    let data = serde_json::to_vec_pretty(&bundle).map_err(|_| CliErrorKind::Usage)?;
    write_generated_output_file(path, &data)
}

#[cfg(feature = "operator_tools")]
fn read_peak_proof_bundle(path: &Path) -> Result<PeakProofBundleJson, CliErrorKind> {
    require_file_exists(path, "peak proof")?;
    let bytes = std::fs::read(path).map_err(|_| CliErrorKind::Usage)?;
    let bundle: PeakProofBundleJson =
        serde_json::from_slice(&bytes).map_err(|_| CliErrorKind::Usage)?;
    if bundle.schema != "mneme.audit.peak_consistency_proof.v1" {
        return Err(CliErrorKind::Usage);
    }
    Ok(bundle)
}

#[cfg(feature = "operator_tools")]
fn read_peak_frontier_proof_bundle(
    path: &Path,
) -> Result<PeakFrontierProofBundleJson, CliErrorKind> {
    require_file_exists(path, "peak frontier proof")?;
    let bytes = std::fs::read(path).map_err(|_| CliErrorKind::Usage)?;
    let bundle: PeakFrontierProofBundleJson =
        serde_json::from_slice(&bytes).map_err(|_| CliErrorKind::Usage)?;
    if bundle.schema != "mneme.audit.peak_frontier_proof.v1"
        || bundle.proof_kind != "structural_frontier.v1"
        || bundle.claim != "structural_frontier_only"
        || bundle.signature_coverage != "none_for_appended_subtrees"
        || !bundle.requires_external_pin
        || !bundle.signed_checkpoint_delta_required_for_signature_coverage
    {
        return Err(CliErrorKind::Usage);
    }
    Ok(bundle)
}

#[cfg(feature = "operator_tools")]
fn read_peak_inclusion_proof_bundle(
    path: &Path,
) -> Result<PeakInclusionProofBundleJson, CliErrorKind> {
    require_file_exists(path, "peak inclusion proof")?;
    let bytes = std::fs::read(path).map_err(|_| CliErrorKind::Usage)?;
    let bundle: PeakInclusionProofBundleJson =
        serde_json::from_slice(&bytes).map_err(|_| CliErrorKind::Usage)?;
    if bundle.schema != "mneme.audit.peak_inclusion_proof.v1" {
        return Err(CliErrorKind::Usage);
    }
    Ok(bundle)
}

#[cfg(feature = "operator_tools")]
fn trusted_operator_keys(
    operator_pubkey: Option<&str>,
    seed_hex: Option<&str>,
) -> Result<Vec<[u8; 32]>, CliErrorKind> {
    let from_pubkey = operator_pubkey.map(parse_seed_hex).transpose()?;
    let from_seed = seed_hex
        .map(|seed| Ok(KeyPair::from_seed(parse_seed_hex(seed)?).public_key_bytes()))
        .transpose()?;
    match (from_pubkey, from_seed) {
        (Some(pubkey), Some(seed_pubkey)) if pubkey != seed_pubkey => {
            Err(CliErrorKind::VerifyFailed(MnemeError::RootSigInvalid))
        }
        (Some(pubkey), _) | (None, Some(pubkey)) => Ok(vec![pubkey]),
        (None, None) => {
            eprintln!(
                "mneme: offline proof verification requires --operator-pubkey or --operator-seed"
            );
            Err(CliErrorKind::Usage)
        }
    }
}

#[cfg(feature = "operator_tools")]
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
    mneme_store::reject_store_path_aliases(store).map_err(CliErrorKind::Kernel)?;
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
    write_generated_output_file(path, &bytes)
}

fn validate_generated_output_path(path: &Path) -> Result<(), CliErrorKind> {
    generated_output::validate_path(path).map_err(|err| generated_output_error_to_usage(path, err))
}

fn write_generated_output_file(path: &Path, data: &[u8]) -> Result<(), CliErrorKind> {
    generated_output::write_file(path, data)
        .map_err(|err| generated_output_error_to_usage(path, err))
}

fn generated_output_error_to_usage(
    path: &Path,
    err: generated_output::GeneratedOutputError,
) -> CliErrorKind {
    eprintln!("mneme: {err}: {}", path.display());
    CliErrorKind::Usage
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

//! `mneme` CLI — adoption-layer fail-closed gate (blueprint §14.2).

mod attest;
mod cert;
mod determinism;

use clap::{Parser, Subcommand, ValueEnum};
use mneme_cap::agent_cap;
use mneme_core::{
    DistanceMetric, Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Procedure,
    ProcedureAlgo, Query, RetrievalProofLevel, TrustTier,
};
use mneme_crypto::{EnvelopeKeyVault, KeyPair, TrustConfig};
use mneme_store::Store;
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

    /// Operator seed as 32-byte hex (64 hex chars), e.g. `00..01`; generated and stored on first use if absent
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
    },
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
    Init { path: PathBuf },
    /// Determinism foundation gate (§17.7)
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
        Commands::Forget { store, key, mode } => {
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
            mneme_store
                .forget(ForgetTarget::LogicalKey(logical_key), &cap, forget_mode)
                .map_err(CliErrorKind::Kernel)?;
            println!("forgot key {key}");
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
        Commands::Audit { root: _root } => {
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
    let seed_path = store.join(".operator_seed");
    if let Some(hex) = seed_hex {
        return Ok(KeyPair::from_seed(parse_seed_hex(hex)?));
    }
    if seed_path.exists() {
        let hex = std::fs::read_to_string(&seed_path).map_err(|_| CliErrorKind::Usage)?;
        return Ok(KeyPair::from_seed(parse_seed_hex(hex.trim())?));
    }
    let (operator, seed) = KeyPair::generate_with_seed();
    std::fs::create_dir_all(store).ok();
    std::fs::write(&seed_path, hex::encode(seed)).map_err(|_| CliErrorKind::Usage)?;
    Ok(operator)
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

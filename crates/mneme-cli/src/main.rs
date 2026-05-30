//! `mneme` CLI — adoption-layer fail-closed gate (blueprint §14.2).

mod attest;
mod determinism;

use clap::{Parser, Subcommand, ValueEnum};
use mneme_cap::agent_cap;
use mneme_core::{
    Draft, ForgetMode, ForgetTarget, LogicalKey, MemoryKind, MnemeError, Query, TrustTier,
};
use mneme_crypto::{KeyPair, TrustConfig};
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

    /// Operator seed file (32 bytes hex) for store crypto; generated on first use if missing
    #[arg(long, global = true, env = "MNEME_OPERATOR_SEED")]
    operator_seed: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Fail-closed: exit 0 iff root and reachable proofs verify (§14.2)
    Verify { store: PathBuf },
    /// Print provenance, writers, tiers, tombstones for a root checkpoint
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
    /// Emit a Sigstore-signable attestation over a root (§15.2)
    Attest { root: PathBuf },
    /// Initialize a new store at PATH
    Init { path: PathBuf },
    /// Determinism foundation gate (§17.7)
    Determinism {
        #[command(subcommand)]
        command: DeterminismCommands,
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum CliErrorKind {
    Usage,
    StoreUnavailable,
    VerifyFailed,
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
                CliErrorKind::VerifyFailed => (4, "verify failed".to_string()),
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
            Store::create(&path, operator).map_err(CliErrorKind::Kernel)?;
            println!("initialized store at {}", path.display());
            Ok(())
        }
        Commands::Verify { store } => {
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let trust = TrustConfig::new(operator.public_key_bytes());
            let report = verify_store(&store, &trust).map_err(|_| CliErrorKind::VerifyFailed)?;
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
        } => {
            if query.trim().is_empty() && key.is_none() {
                eprintln!("mneme: recall requires --query or --key");
                return Err(CliErrorKind::Usage);
            }
            require_store_dir(&store)?;
            let operator = load_or_generate_operator(&store, cli.operator_seed.as_deref())?;
            let mut mneme_store =
                Store::open(&store, operator.clone()).map_err(CliErrorKind::Kernel)?;
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
            let mut mneme_store =
                Store::open(&store, operator.clone()).map_err(CliErrorKind::Kernel)?;
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
            let mut mneme_store =
                Store::open(&store, operator.clone()).map_err(CliErrorKind::Kernel)?;
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
        Commands::Merge { store_a, store_b } => {
            require_store_dir(&store_a)?;
            require_store_dir(&store_b)?;
            let operator = load_or_generate_operator(&store_a, cli.operator_seed.as_deref())?;
            let mut mneme_store = Store::open(&store_a, operator).map_err(CliErrorKind::Kernel)?;
            let root = mneme_store
                .merge_from_path(&store_b)
                .map_err(CliErrorKind::Kernel)?;
            println!(
                "merged root preimage_hash={}",
                hex::encode(root.preimage_hash)
            );
            Ok(())
        }
        Commands::Audit { root } => require_path_exists(&root, "root checkpoint"),
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

fn require_path_exists(path: &Path, label: &str) -> Result<(), CliErrorKind> {
    require_file_exists(path, label)?;
    Err(CliErrorKind::StoreUnavailable)
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

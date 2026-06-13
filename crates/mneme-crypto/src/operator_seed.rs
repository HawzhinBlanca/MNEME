//! Operator signing-seed custody shared by CLI, daemon, and MCP frontends.

use mneme_core::MnemeError;
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use crate::aead::{open, random_nonce, seal};
use crate::keys::KeyPair;
use crate::types::{OBJECT_KEY_LEN, XCHACHA_NONCE_LEN, nonce_from_slice};
use crate::vault::{
    SecretFileMode, durability_fsync_enabled, entry_exists, io_error, read_single_link_file,
    sync_parent_dir, write_new_secret_file,
};

const OPERATOR_SEED_AAD: &[u8] = b"mneme-operator-seed-v1";
const OPERATOR_SEED_LEN: usize = 32;
const WRAPPED_OPERATOR_SEED_LEN: usize = XCHACHA_NONCE_LEN + OPERATOR_SEED_LEN + 16;

/// Load or create the store operator keypair.
///
/// Explicit `seed_hex` / `MNEME_OPERATOR_SEED` values are process-custody overrides
/// and are never persisted. When `MNEME_KMS_MASTER_KEY_HEX` is set, generated or
/// legacy seeds are sealed under that master at `keys/operator_seed.sealed`; the
/// old plaintext `.operator_seed` file is migrated then removed. Without either an
/// explicit seed or a master, operator seed custody fails closed.
pub fn load_or_generate_operator(
    store: &Path,
    seed_hex: Option<&str>,
) -> Result<KeyPair, MnemeError> {
    let env_seed = std::env::var("MNEME_OPERATOR_SEED").ok();
    let master_hex = std::env::var("MNEME_KMS_MASTER_KEY_HEX").ok();
    load_or_generate_operator_with_env(store, seed_hex, env_seed.as_deref(), master_hex.as_deref())
}

fn load_or_generate_operator_with_env(
    store: &Path,
    seed_hex: Option<&str>,
    env_seed_hex: Option<&str>,
    master_hex: Option<&str>,
) -> Result<KeyPair, MnemeError> {
    if let Some(hex) = seed_hex {
        return keypair_from_seed_hex(hex);
    }
    if let Some(hex) = env_seed_hex {
        return keypair_from_seed_hex(hex.trim());
    }
    if let Some(hex) = master_hex {
        let master = parse_master_hex(hex.trim())?;
        return load_or_create_sealed_operator(store, &master);
    }
    Err(MnemeError::KeyVaultMissing)
}

fn load_or_create_sealed_operator(
    store: &Path,
    master: &[u8; OBJECT_KEY_LEN],
) -> Result<KeyPair, MnemeError> {
    let sealed_path = sealed_operator_seed_path(store);
    if entry_exists(&sealed_path)? {
        let seed = read_sealed_operator_seed(&sealed_path, master)?;
        return Ok(keypair_from_seed(seed));
    }

    let legacy_path = legacy_operator_seed_path(store);
    if entry_exists(&legacy_path)? {
        let seed = read_legacy_operator_seed(&legacy_path)?;
        write_sealed_operator_seed(&sealed_path, master, &seed)?;
        fs::remove_file(&legacy_path)
            .map_err(|e| io_error(legacy_path.display().to_string(), e))?;
        if durability_fsync_enabled() {
            sync_parent_dir(&legacy_path)?;
        }
        return Ok(keypair_from_seed(seed));
    }

    let (operator, mut seed) = KeyPair::generate_with_seed();
    write_sealed_operator_seed(&sealed_path, master, &seed)?;
    seed.zeroize();
    Ok(operator)
}

fn read_sealed_operator_seed(
    path: &Path,
    master: &[u8; OBJECT_KEY_LEN],
) -> Result<[u8; OPERATOR_SEED_LEN], MnemeError> {
    let bytes = read_single_link_file(path)?;
    if bytes.len() != WRAPPED_OPERATOR_SEED_LEN {
        return Err(MnemeError::KeyVaultCorrupt);
    }
    let nonce =
        nonce_from_slice(&bytes[..XCHACHA_NONCE_LEN]).map_err(|_| MnemeError::KeyVaultCorrupt)?;
    let opened = open(
        master,
        &nonce,
        &bytes[XCHACHA_NONCE_LEN..],
        OPERATOR_SEED_AAD,
    )?;
    seed_from_bytes(&opened).map_err(|_| MnemeError::KeyVaultCorrupt)
}

fn write_sealed_operator_seed(
    path: &Path,
    master: &[u8; OBJECT_KEY_LEN],
    seed: &[u8; OPERATOR_SEED_LEN],
) -> Result<(), MnemeError> {
    let nonce = random_nonce();
    let ct = seal(master, &nonce, seed, OPERATOR_SEED_AAD)?;
    let mut wrapped = Vec::with_capacity(WRAPPED_OPERATOR_SEED_LEN);
    wrapped.extend_from_slice(&nonce);
    wrapped.extend_from_slice(&ct);
    write_operator_seed_file(path, &wrapped)
}

fn read_legacy_operator_seed(path: &Path) -> Result<[u8; OPERATOR_SEED_LEN], MnemeError> {
    let bytes = read_single_link_file(path)?;
    let hex = std::str::from_utf8(&bytes).map_err(|_| MnemeError::CapMalformed)?;
    parse_operator_seed_hex(hex.trim())
}

fn write_operator_seed_file(path: &Path, bytes: &[u8]) -> Result<(), MnemeError> {
    write_new_secret_file(path, bytes, SecretFileMode::OwnerOnly)
}

fn keypair_from_seed_hex(hex: &str) -> Result<KeyPair, MnemeError> {
    let seed = parse_operator_seed_hex(hex)?;
    Ok(keypair_from_seed(seed))
}

fn keypair_from_seed(mut seed: [u8; OPERATOR_SEED_LEN]) -> KeyPair {
    let operator = KeyPair::from_seed(seed);
    seed.zeroize();
    operator
}

fn parse_operator_seed_hex(hex_str: &str) -> Result<[u8; OPERATOR_SEED_LEN], MnemeError> {
    let bytes = hex::decode(hex_str).map_err(|_| MnemeError::CapMalformed)?;
    seed_from_bytes(&bytes).map_err(|_| MnemeError::CapMalformed)
}

fn parse_master_hex(hex_str: &str) -> Result<[u8; OBJECT_KEY_LEN], MnemeError> {
    let bytes = hex::decode(hex_str).map_err(|_| MnemeError::KeyVaultCorrupt)?;
    seed_from_bytes(&bytes).map_err(|_| MnemeError::KeyVaultCorrupt)
}

fn seed_from_bytes<const N: usize>(bytes: &[u8]) -> Result<[u8; N], ()> {
    if bytes.len() != N {
        return Err(());
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn sealed_operator_seed_path(store: &Path) -> PathBuf {
    store.join("keys").join("operator_seed.sealed")
}

fn legacy_operator_seed_path(store: &Path) -> PathBuf {
    store.join(".operator_seed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn tempdir(context: &str) -> TempDir {
        tempfile::tempdir().unwrap_or_else(|err| panic!("{context}: tempdir failed: {err}"))
    }

    #[test]
    fn envelope_master_writes_sealed_operator_seed_without_plaintext_file() {
        let dir = tempdir("sealed operator seed");
        let master = "42".repeat(32);

        let operator_a = load_or_generate_operator_with_env(dir.path(), None, None, Some(&master))
            .expect("create sealed operator");
        let operator_b = load_or_generate_operator_with_env(dir.path(), None, None, Some(&master))
            .expect("reopen sealed operator");

        assert_eq!(operator_a.public_key_bytes(), operator_b.public_key_bytes());
        assert!(
            sealed_operator_seed_path(dir.path()).exists(),
            "KMS-backed operator seed should be sealed"
        );
        assert!(
            !legacy_operator_seed_path(dir.path()).exists(),
            "KMS-backed operator seed must not create plaintext .operator_seed"
        );
        let sealed = fs::read(sealed_operator_seed_path(dir.path())).expect("sealed seed bytes");
        assert_eq!(sealed.len(), WRAPPED_OPERATOR_SEED_LEN);
    }

    #[test]
    fn envelope_master_migrates_existing_plaintext_operator_seed() {
        let dir = tempdir("operator seed migration");
        let master = "24".repeat(32);
        let seed = "11".repeat(32);
        let expected = KeyPair::from_seed([0x11; 32]).public_key_bytes();
        fs::write(legacy_operator_seed_path(dir.path()), &seed).expect("legacy seed");

        let operator = load_or_generate_operator_with_env(dir.path(), None, None, Some(&master))
            .expect("migrate seed");

        assert_eq!(operator.public_key_bytes(), expected);
        assert!(sealed_operator_seed_path(dir.path()).exists());
        assert!(!legacy_operator_seed_path(dir.path()).exists());
    }

    #[test]
    fn no_master_without_explicit_seed_fails_closed_without_plaintext_file() {
        let dir = tempdir("no plaintext operator seed");

        let err = match load_or_generate_operator_with_env(dir.path(), None, None, None) {
            Ok(_) => panic!("missing operator seed custody should fail closed"),
            Err(err) => err,
        };

        assert_eq!(err, MnemeError::KeyVaultMissing);
        assert!(
            !legacy_operator_seed_path(dir.path()).exists(),
            "operator seed custody must not fall back to plaintext .operator_seed"
        );
        assert!(
            !sealed_operator_seed_path(dir.path()).exists(),
            "missing master must not create a sealed seed with an implicit key"
        );
    }

    #[test]
    fn sealed_operator_seed_round_trips_across_reopen() {
        let dir = tempdir("sealed operator round trip");
        let master = "33".repeat(32);
        let operator_a = load_or_generate_operator_with_env(dir.path(), None, None, Some(&master))
            .expect("create sealed operator");
        let operator_b = load_or_generate_operator_with_env(dir.path(), None, None, Some(&master))
            .expect("reopen sealed operator");

        assert_eq!(operator_a.public_key_bytes(), operator_b.public_key_bytes());
    }

    #[test]
    fn sealed_operator_seed_tamper_fails_closed() {
        let dir = tempdir("sealed operator tamper");
        let master = "55".repeat(32);
        let _ = load_or_generate_operator_with_env(dir.path(), None, None, Some(&master))
            .expect("create sealed operator");

        let path = sealed_operator_seed_path(dir.path());
        let mut sealed = fs::read(&path).expect("sealed seed bytes");
        let tamper_index = sealed.len() - 1;
        sealed[tamper_index] ^= 0x01;
        fs::write(&path, &sealed).expect("tampered sealed seed");

        let err = match load_or_generate_operator_with_env(dir.path(), None, None, Some(&master)) {
            Ok(_) => panic!("tampered sealed operator seed should fail closed"),
            Err(err) => err,
        };
        assert_eq!(err, MnemeError::ObjectTampered);
    }

    #[test]
    fn sealed_operator_seed_wrong_master_fails_closed() {
        let dir = tempdir("sealed operator wrong master");
        let master = "66".repeat(32);
        let _ = load_or_generate_operator_with_env(dir.path(), None, None, Some(&master))
            .expect("create sealed operator");

        let wrong_master = "77".repeat(32);
        let err =
            match load_or_generate_operator_with_env(dir.path(), None, None, Some(&wrong_master)) {
                Ok(_) => panic!("wrong master must not decrypt sealed operator seed"),
                Err(err) => err,
            };
        assert_eq!(err, MnemeError::ObjectTampered);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_sealed_operator_seed_fails_closed_without_following_target() {
        let dir = tempdir("sealed operator symlink");
        let master = "88".repeat(32);
        let _ = load_or_generate_operator_with_env(dir.path(), None, None, Some(&master))
            .expect("create sealed operator");
        let sealed = sealed_operator_seed_path(dir.path());
        let external = dir.path().join("external-sealed-seed");
        fs::rename(&sealed, &external).expect("move sealed seed fixture");
        std::os::unix::fs::symlink(&external, &sealed).expect("sealed seed symlink");

        let err = match load_or_generate_operator_with_env(dir.path(), None, None, Some(&master)) {
            Ok(_) => panic!("symlinked sealed operator seed should fail closed"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("FilesystemLoop") || err.to_string().contains("symlink"));
        assert!(
            fs::symlink_metadata(&sealed)
                .expect("sealed symlink metadata")
                .file_type()
                .is_symlink(),
            "failed read must not replace the sealed seed symlink"
        );
        assert!(external.exists(), "external target must not be destroyed");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_legacy_operator_seed_is_not_migrated_or_removed() {
        let dir = tempdir("legacy operator symlink");
        let master = "99".repeat(32);
        let legacy = legacy_operator_seed_path(dir.path());
        let external = dir.path().join("external-legacy-seed");
        let seed = "11".repeat(32);
        fs::write(&external, &seed).expect("external legacy seed");
        std::os::unix::fs::symlink(&external, &legacy).expect("legacy seed symlink");

        let err = match load_or_generate_operator_with_env(dir.path(), None, None, Some(&master)) {
            Ok(_) => panic!("symlinked legacy operator seed should fail closed"),
            Err(err) => err,
        };

        assert!(err.to_string().contains("FilesystemLoop") || err.to_string().contains("symlink"));
        assert!(
            fs::symlink_metadata(&legacy)
                .expect("legacy symlink metadata")
                .file_type()
                .is_symlink(),
            "failed migration must not remove the legacy seed symlink"
        );
        assert_eq!(
            fs::read_to_string(&external).expect("external legacy seed read"),
            seed,
            "failed migration must not modify the external seed target"
        );
        assert!(
            !sealed_operator_seed_path(dir.path()).exists(),
            "failed migration must not create a sealed operator seed"
        );
    }

    #[test]
    fn no_master_existing_plaintext_seed_is_not_loaded() {
        let dir = tempdir("legacy plaintext without master");
        let seed = "11".repeat(32);
        fs::write(legacy_operator_seed_path(dir.path()), &seed).expect("legacy seed");

        let err = match load_or_generate_operator_with_env(dir.path(), None, None, None) {
            Ok(_) => panic!("legacy plaintext seed should require an envelope master to migrate"),
            Err(err) => err,
        };

        assert_eq!(err, MnemeError::KeyVaultMissing);
        assert!(
            legacy_operator_seed_path(dir.path()).exists(),
            "missing master should not destroy an operator seed that can still be migrated"
        );
        assert!(!sealed_operator_seed_path(dir.path()).exists());
    }
}

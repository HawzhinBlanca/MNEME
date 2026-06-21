//! CCR-Shapley — certified Monte-Carlo attribution of a verified context.
//!
//! `mneme shapley` replays sampled coalitions (prefix sets of deterministic
//! blake3-seeded permutations) of a fail-closed verified context through a
//! user-supplied JUDGE command, counts for each entry how often *adding it*
//! changed the judge's output hash, and emits a signed offline-verifiable
//! certificate of the per-entry marginal-impact counts.
//!
//! Estimated Shapley value of entry i = counts[i] / samples (binary marginal:
//! "did the outcome change when i joined the coalition"). Integer counts only —
//! no floating point anywhere (determinism discipline).
//!
//! HONESTY BOUNDARY (do not weaken): scores are Monte-Carlo estimates of
//! marginal impact **relative to the supplied judge function**. The judge is
//! named (its command string is hash-bound into the certificate) but its
//! execution is NOT attested — attested judges are strong mode, gated on
//! deterministic inference. This proves which verified memories changed the
//! judge's output under the signed root; it never proves semantic truth.
//! Authenticated ≠ true.

use crate::replay::{Reader, put_id_list, put_str};
use mneme_core::MnemeError;
use mneme_crypto::{KeyPair, sign_message, verify_signature_bytes, verifying_key_from_bytes};

pub const SHAPLEY_CERT_VERSION: u16 = 1;
const PAYLOAD_DOMAIN: &[u8] = b"MNEME-shapley-cert-v1";

pub const SHAPLEY_HONESTY: &str = "Monte-Carlo marginal-impact attribution relative to the \
SUPPLIED judge command (hash-bound, execution NOT attested; attested judges are strong mode \
pending deterministic inference); proves which verified memories changed the judge output \
under the signed root — never semantic truth; authenticated != true";

/// Signed attribution certificate over a verified context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShapleyCertV1 {
    pub root_seq: u64,
    pub root_preimage: [u8; 32],
    pub namespace: String,
    pub keys: Vec<String>,
    pub ids: Vec<[u8; 32]>,
    /// BLAKE3 of the judge command string (names the outcome function).
    pub judge_hash: [u8; 32],
    pub seed: [u8; 32],
    pub samples: u32,
    /// counts[i] = number of sampled permutations where adding ids[i] changed
    /// the judge output hash. Estimated Shapley value = counts[i] / samples.
    pub counts: Vec<u32>,
    pub operator_pk: [u8; 32],
    pub sig: [u8; 64],
}

impl ShapleyCertV1 {
    fn payload(&self) -> Result<Vec<u8>, MnemeError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(PAYLOAD_DOMAIN);
        out.extend_from_slice(&SHAPLEY_CERT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.root_seq.to_le_bytes());
        out.extend_from_slice(&self.root_preimage);
        put_str(&mut out, &self.namespace)?;
        let nkeys: u16 = self
            .keys
            .len()
            .try_into()
            .map_err(|_| MnemeError::SchemaDrift)?;
        out.extend_from_slice(&nkeys.to_le_bytes());
        for k in &self.keys {
            put_str(&mut out, k)?;
        }
        put_id_list(&mut out, &self.ids)?;
        out.extend_from_slice(&self.judge_hash);
        out.extend_from_slice(&self.seed);
        out.extend_from_slice(&self.samples.to_le_bytes());
        let ncounts: u16 = self
            .counts
            .len()
            .try_into()
            .map_err(|_| MnemeError::SchemaDrift)?;
        out.extend_from_slice(&ncounts.to_le_bytes());
        for c in &self.counts {
            out.extend_from_slice(&c.to_le_bytes());
        }
        out.extend_from_slice(&self.operator_pk);
        Ok(out)
    }

    pub fn sign_and_encode(mut self, operator: &KeyPair) -> Result<Vec<u8>, MnemeError> {
        self.operator_pk = operator.public_key_bytes();
        let payload = self.payload()?;
        self.sig = sign_message(operator.signing_key(), &payload);
        let mut wire = payload;
        wire.extend_from_slice(&self.sig);
        Ok(wire)
    }

    /// Strict fail-closed decode + signature + internal-consistency checks.
    pub fn verify(wire: &[u8], pinned_pk: Option<&[u8; 32]>) -> Result<Self, MnemeError> {
        let mut r = Reader::new(wire);
        r.expect(PAYLOAD_DOMAIN)?;
        let version = u16::from_le_bytes(r.take_arr::<2>()?);
        if version != SHAPLEY_CERT_VERSION {
            return Err(MnemeError::UnsupportedVersion { got: version });
        }
        let root_seq = u64::from_le_bytes(r.take_arr::<8>()?);
        let root_preimage = r.take_arr::<32>()?;
        let namespace = r.take_str()?;
        let nkeys = u16::from_le_bytes(r.take_arr::<2>()?);
        let mut keys = Vec::with_capacity(usize::from(nkeys));
        for _ in 0..nkeys {
            keys.push(r.take_str()?);
        }
        let ids = r.take_id_list()?;
        let judge_hash = r.take_arr::<32>()?;
        let seed = r.take_arr::<32>()?;
        let samples = u32::from_le_bytes(r.take_arr::<4>()?);
        let ncounts = u16::from_le_bytes(r.take_arr::<2>()?);
        let mut counts = Vec::with_capacity(usize::from(ncounts));
        for _ in 0..ncounts {
            counts.push(u32::from_le_bytes(r.take_arr::<4>()?));
        }
        let operator_pk = r.take_arr::<32>()?;
        let payload_len = r.consumed();
        let sig = r.take_arr::<64>()?;
        r.expect_end()?;

        if let Some(pk) = pinned_pk {
            if pk != &operator_pk {
                return Err(MnemeError::RootSigInvalid);
            }
        }
        let vk = verifying_key_from_bytes(&operator_pk)?;
        verify_signature_bytes(&vk, &wire[..payload_len], &sig)?;

        // Internal consistency: one count per id, no count above samples, and a
        // nonzero sample budget.
        if counts.len() != ids.len() || samples == 0 || counts.iter().any(|c| *c > samples) {
            return Err(MnemeError::SchemaDrift);
        }

        Ok(Self {
            root_seq,
            root_preimage,
            namespace,
            keys,
            ids,
            judge_hash,
            seed,
            samples,
            counts,
            operator_pk,
            sig,
        })
    }
}

/// Deterministic permutation stream: Fisher–Yates driven by BLAKE3 XOF over
/// (seed, sample index). No ambient randomness (determinism discipline).
pub fn permutation(seed: &[u8; 32], sample: u32, n: usize) -> Vec<usize> {
    let mut h = blake3::Hasher::new();
    h.update(b"MNEME-shapley-perm-v1");
    h.update(seed);
    h.update(&sample.to_le_bytes());
    let mut xof = h.finalize_xof();
    let mut perm: Vec<usize> = (0..n).collect();
    for i in (1..n).rev() {
        let mut buf = [0u8; 8];
        xof.fill(&mut buf);
        // Modulo bias is negligible for n << 2^64 and irrelevant to soundness:
        // the certificate binds the seed, so the sampling is re-derivable.
        let j = (u64::from_le_bytes(buf) % (i as u64 + 1)) as usize;
        perm.swap(i, j);
    }
    perm
}

/// Run the judge over the coalition context (entries in canonical context
/// order) and return the BLAKE3 hash of its stdout. The judge command is split
/// on whitespace; the context is fed on stdin as `<id-hex>\n<body>\n\n` per entry.
pub fn judge_outcome(
    judge_cmd: &str,
    entries: &[([u8; 32], Vec<u8>)],
    include: &[bool],
) -> Result<[u8; 32], MnemeError> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut parts = judge_cmd.split_whitespace();
    let bin = parts.next().ok_or(MnemeError::SchemaDrift)?;
    let mut child = Command::new(bin)
        .args(parts)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| MnemeError::SchemaDrift)?;
    {
        let stdin = child.stdin.as_mut().ok_or(MnemeError::SchemaDrift)?;
        for (idx, (id, body)) in entries.iter().enumerate() {
            if !include[idx] {
                continue;
            }
            stdin
                .write_all(hex::encode(id).as_bytes())
                .and_then(|()| stdin.write_all(b"\n"))
                .and_then(|()| stdin.write_all(body))
                .and_then(|()| stdin.write_all(b"\n\n"))
                .map_err(|_| MnemeError::SchemaDrift)?;
        }
    }
    let out = child
        .wait_with_output()
        .map_err(|_| MnemeError::SchemaDrift)?;
    let mut h = blake3::Hasher::new();
    h.update(b"MNEME-shapley-outcome-v1");
    h.update(&out.stdout);
    Ok(*h.finalize().as_bytes())
}

/// Monte-Carlo marginal-impact counts: for each sampled permutation, walk it
/// prefix-by-prefix; counts[i] += 1 when adding entry i changes the outcome.
pub fn sample_counts(
    judge_cmd: &str,
    entries: &[([u8; 32], Vec<u8>)],
    seed: &[u8; 32],
    samples: u32,
) -> Result<Vec<u32>, MnemeError> {
    let n = entries.len();
    let mut counts = vec![0u32; n];
    for s in 0..samples {
        let perm = permutation(seed, s, n);
        let mut include = vec![false; n];
        let mut prev = judge_outcome(judge_cmd, entries, &include)?;
        for &i in &perm {
            include[i] = true;
            let next = judge_outcome(judge_cmd, entries, &include)?;
            if next != prev {
                counts[i] = counts[i].saturating_add(1);
            }
            prev = next;
        }
    }
    Ok(counts)
}

pub fn judge_hash(judge_cmd: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MNEME-shapley-judge-v1");
    h.update(judge_cmd.as_bytes());
    *h.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_cert(op: &KeyPair) -> ShapleyCertV1 {
        ShapleyCertV1 {
            root_seq: 9,
            root_preimage: [0xcd; 32],
            namespace: "user".into(),
            keys: vec!["a".into(), "b".into()],
            ids: vec![[0x11; 32], [0x22; 32]],
            judge_hash: judge_hash("cat"),
            seed: [0x42; 32],
            samples: 16,
            counts: vec![16, 0],
            operator_pk: op.public_key_bytes(),
            sig: [0; 64],
        }
    }

    #[test]
    fn roundtrip_sign_verify() {
        let op = KeyPair::from_seed([9u8; 32]);
        let wire = sample_cert(&op).sign_and_encode(&op).expect("encode");
        let cert = ShapleyCertV1::verify(&wire, Some(&op.public_key_bytes())).expect("verify");
        assert_eq!(cert.counts, vec![16, 0]);
    }

    #[test]
    fn every_byte_flip_fails_closed() {
        let op = KeyPair::from_seed([9u8; 32]);
        let wire = sample_cert(&op).sign_and_encode(&op).expect("encode");
        for i in 0..wire.len() {
            let mut bad = wire.clone();
            bad[i] ^= 0x01;
            assert!(
                ShapleyCertV1::verify(&bad, None).is_err(),
                "byte flip at {i} must fail closed"
            );
        }
    }

    #[test]
    fn count_above_samples_rejected_even_if_signed() {
        let op = KeyPair::from_seed([9u8; 32]);
        let mut c = sample_cert(&op);
        c.counts = vec![17, 0]; // exceeds samples=16
        let wire = c.sign_and_encode(&op).expect("encode");
        assert!(matches!(
            ShapleyCertV1::verify(&wire, None),
            Err(MnemeError::SchemaDrift)
        ));
    }

    #[test]
    fn permutations_are_deterministic_and_cover() {
        let seed = [7u8; 32];
        let p1 = permutation(&seed, 3, 5);
        let p2 = permutation(&seed, 3, 5);
        assert_eq!(p1, p2);
        let mut sorted = p1.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, vec![0, 1, 2, 3, 4]);
        assert_ne!(permutation(&seed, 4, 5), p1, "different sample index");
    }

    #[test]
    fn marginal_counts_attribute_to_the_load_bearing_entry() {
        // Judge = `grep -c 91C` style via /bin/sh is exercised in the CLI e2e;
        // here use `cat`: output changes whenever ANY entry joins, so every
        // entry gets full counts — the degenerate sanity case.
        let entries = vec![([0x11; 32], b"one".to_vec()), ([0x22; 32], b"two".to_vec())];
        let counts = sample_counts("cat", &entries, &[1u8; 32], 4).expect("counts");
        assert_eq!(counts, vec![4, 4]);
    }
}

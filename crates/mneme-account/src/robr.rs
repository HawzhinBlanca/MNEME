//! ROBR — Recall-to-Output Binding Receipt (capability 1, task ROBR-1: the envelope).
//!
//! A signed, offline-verifiable envelope that binds a model output commitment to the
//! EXACT inputs that produced it:
//!
//!   envelope = H( memory_root ‖ prompt ‖ weight_measurement ‖ sampling_params ‖ context )
//!   receipt  = sig_operator( envelope ‖ output_token_commit ‖ … )
//!
//! i.e. "under signed memory root R, prompt P, model-weight measurement W, sampling
//! params S, and the verified context C assembled from N fail-closed recalls, the
//! produced output is committed to as O." Anyone can recompute the envelope from the
//! carried fields and check the signature offline.
//!
//! HONESTY BOUNDARY (do not weaken):
//!   ROBR-1 is the BINDING receipt only. It cryptographically binds the output
//!   commitment to this memory root + prompt + weight measurement + sampling params +
//!   verified context. It does NOT prove the model actually produced that output — that
//!   requires re-execution (ROBR-2 replay-verify, no TEE) or hardware attestation
//!   (ROBR-4 TEE). `weight_measurement` is OPERATOR-ASSERTED here; it becomes trusted
//!   only under a TEE measurement (ROBR-4). And it NEVER proves semantic truth —
//!   authenticated != true.
//!
//! Relocated from mneme-cli to mneme-account so the store kernel can mint receipts
//! (`Store::create_robr_receipt`). Self-contained strict fail-closed wire: unknown
//! version, length mismatch, or trailing bytes ⇒ typed error; the signature covers the
//! full payload.

use mneme_core::MnemeError;
use mneme_crypto::{KeyPair, sign_message, verify_signature_bytes, verifying_key_from_bytes};

pub const ROBR_RECEIPT_VERSION: u16 = 1;
const PAYLOAD_DOMAIN: &[u8] = b"MNEME-robr-receipt-v1";
const ENVELOPE_DOMAIN: &[u8] = b"MNEME-robr-envelope-v1";
const CONTEXT_DOMAIN: &[u8] = b"MNEME-robr-context-v1";
const REFERENCE_KERNEL_DOMAIN: &[u8] = b"MNEME-robr-reference-kernel-v1";

pub const ROBR_HONESTY: &str = "binding receipt only: cryptographically binds the output \
commitment to this signed memory root, prompt, operator-asserted weight measurement, sampling \
params, and verified context; it does NOT prove the model produced the output (that needs \
ROBR-2 replay or ROBR-4 TEE attestation) and never proves semantic truth — authenticated != true";

pub const ROBR_REPLAY_HONESTY: &str = "replay verified: the committed output is the bit-identical \
deterministic output of the DECLARED reference kernel on the committed inputs (root, prompt, \
weights, sampling, context) — re-executed, not merely asserted. The reference kernel is a \
deterministic stand-in; binding the output to a REAL model requires a batch-invariant inference \
backend (and ROBR-4 TEE for hardware attestation of the weights). Never semantic truth — \
authenticated != true";

/// Offline-verifiable ROBR binding receipt (v1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RobrReceiptV1 {
    /// Sequence of the signed memory root the context was assembled under.
    pub root_seq: u64,
    /// Preimage hash of that signed root (binds to the exact memory state).
    pub root_preimage: [u8; 32],
    /// BLAKE3 hash of the prompt presented to the model.
    pub prompt_hash: [u8; 32],
    /// Operator-asserted measurement of the model weights (e.g. a digest of the
    /// weights / a TEE measurement under ROBR-4). Trust = operator unless attested.
    pub weight_measurement: [u8; 32],
    /// Canonical sampling parameters (e.g. "model=…;temp=0;top_p=1;seed=42").
    pub sampling_params: String,
    /// Object ids of the verified memories that entered the assembled context.
    pub context_ids: Vec<[u8; 32]>,
    /// Chained hash over the assembled context (id+body pairs in recall order).
    pub context_hash: [u8; 32],
    /// The binding envelope: H(root ‖ prompt ‖ weights ‖ sampling ‖ context).
    pub envelope_hash: [u8; 32],
    /// Commitment to the produced output token stream (BLAKE3 over the tokens).
    pub output_token_commit: [u8; 32],
    pub operator_pk: [u8; 32],
    pub sig: [u8; 64],
}

/// Chained context hash over (id, body) pairs in recall order.
pub fn context_hash(entries: &[([u8; 32], Vec<u8>)]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(CONTEXT_DOMAIN);
    h.update(&(entries.len() as u64).to_le_bytes());
    for (id, body) in entries {
        h.update(id);
        h.update(&(body.len() as u64).to_le_bytes());
        h.update(body);
    }
    *h.finalize().as_bytes()
}

/// The binding envelope.
pub fn envelope_hash(
    root_preimage: &[u8; 32],
    prompt_hash: &[u8; 32],
    weight_measurement: &[u8; 32],
    sampling_params: &str,
    context_hash: &[u8; 32],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(ENVELOPE_DOMAIN);
    h.update(root_preimage);
    h.update(prompt_hash);
    h.update(weight_measurement);
    let sp = sampling_params.as_bytes();
    h.update(&(sp.len() as u64).to_le_bytes());
    h.update(sp);
    h.update(context_hash);
    *h.finalize().as_bytes()
}

/// ROBR-2 deterministic reference kernel. A pure function of the binding envelope:
/// the same committed `(root, prompt, weights, sampling, context)` always yields the
/// same output bytes, bit-for-bit, on any host. This is the replayable stand-in for a
/// model: a real ROBR-2 backend swaps this for a batch-invariant inference kernel.
/// (Output length is itself derived deterministically from the envelope so the stream
/// is not a fixed size.)
pub fn reference_kernel(envelope_hash: &[u8; 32]) -> Vec<u8> {
    let mut h = blake3::Hasher::new();
    h.update(REFERENCE_KERNEL_DOMAIN);
    h.update(envelope_hash);
    let len = 32usize + envelope_hash[0] as usize; // deterministic length in [32, 287]
    let mut reader = h.finalize_xof();
    let mut out = vec![0u8; len];
    reader.fill(&mut out);
    out
}

/// Commitment over a produced output token stream (BLAKE3). Used by both the receipt
/// producer and the replay verifier so the two agree byte-for-byte.
pub fn commit_output(output: &[u8]) -> [u8; 32] {
    *blake3::hash(output).as_bytes()
}

/// ROBR-2 replay check: re-execute the reference kernel over the receipt's committed
/// envelope and assert the resulting output commitment is bit-identical to the one in
/// the receipt. Returns true iff the committed output is the faithful deterministic
/// output of the reference kernel on the committed inputs.
pub fn replay_reproduces_output(receipt: &RobrReceiptV1) -> bool {
    commit_output(&reference_kernel(&receipt.envelope_hash)) == receipt.output_token_commit
}

impl RobrReceiptV1 {
    fn payload(&self) -> Result<Vec<u8>, MnemeError> {
        let mut out = Vec::with_capacity(320);
        out.extend_from_slice(PAYLOAD_DOMAIN);
        out.extend_from_slice(&ROBR_RECEIPT_VERSION.to_le_bytes());
        out.extend_from_slice(&self.root_seq.to_le_bytes());
        out.extend_from_slice(&self.root_preimage);
        out.extend_from_slice(&self.prompt_hash);
        out.extend_from_slice(&self.weight_measurement);
        put_str(&mut out, &self.sampling_params)?;
        put_id_list(&mut out, &self.context_ids)?;
        out.extend_from_slice(&self.context_hash);
        out.extend_from_slice(&self.envelope_hash);
        out.extend_from_slice(&self.output_token_commit);
        out.extend_from_slice(&self.operator_pk);
        Ok(out)
    }

    /// Sign the payload with the operator key and produce the final wire bytes.
    pub fn sign_and_encode(mut self, operator: &KeyPair) -> Result<Vec<u8>, MnemeError> {
        self.operator_pk = operator.public_key_bytes();
        let payload = self.payload()?;
        self.sig = sign_message(operator.signing_key(), &payload);
        let mut wire = payload;
        wire.extend_from_slice(&self.sig);
        Ok(wire)
    }

    /// Strict fail-closed decode + signature + envelope-consistency verification.
    pub fn verify(wire: &[u8], pinned_pk: Option<&[u8; 32]>) -> Result<Self, MnemeError> {
        let mut r = Reader::new(wire);
        r.expect(PAYLOAD_DOMAIN)?;
        let version = u16::from_le_bytes(r.take_arr::<2>()?);
        if version != ROBR_RECEIPT_VERSION {
            return Err(MnemeError::UnsupportedVersion { got: version });
        }
        let root_seq = u64::from_le_bytes(r.take_arr::<8>()?);
        let root_preimage = r.take_arr::<32>()?;
        let prompt_hash = r.take_arr::<32>()?;
        let weight_measurement = r.take_arr::<32>()?;
        let sampling_params = r.take_str()?;
        let context_ids = r.take_id_list()?;
        let context_hash = r.take_arr::<32>()?;
        let envelope_hash_field = r.take_arr::<32>()?;
        let output_token_commit = r.take_arr::<32>()?;
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

        let recomputed = envelope_hash(
            &root_preimage,
            &prompt_hash,
            &weight_measurement,
            &sampling_params,
            &context_hash,
        );
        if recomputed != envelope_hash_field {
            return Err(MnemeError::SchemaDrift);
        }

        Ok(Self {
            root_seq,
            root_preimage,
            prompt_hash,
            weight_measurement,
            sampling_params,
            context_ids,
            context_hash,
            envelope_hash: envelope_hash_field,
            output_token_commit,
            operator_pk,
            sig,
        })
    }
}

/// Strict cursor: every read is bounds-checked; trailing bytes are rejected.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn consumed(&self) -> usize {
        self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], MnemeError> {
        let end = self.pos.checked_add(n).ok_or(MnemeError::SchemaDrift)?;
        let s = self.buf.get(self.pos..end).ok_or(MnemeError::SchemaDrift)?;
        self.pos = end;
        Ok(s)
    }
    fn take_arr<const N: usize>(&mut self) -> Result<[u8; N], MnemeError> {
        let s = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }
    fn expect(&mut self, tag: &[u8]) -> Result<(), MnemeError> {
        if self.take(tag.len())? != tag {
            return Err(MnemeError::SchemaDrift);
        }
        Ok(())
    }
    fn take_str(&mut self) -> Result<String, MnemeError> {
        let len = u16::from_le_bytes(self.take_arr::<2>()?);
        let bytes = self.take(usize::from(len))?;
        String::from_utf8(bytes.to_vec()).map_err(|_| MnemeError::SchemaDrift)
    }
    fn take_id_list(&mut self) -> Result<Vec<[u8; 32]>, MnemeError> {
        let len = u16::from_le_bytes(self.take_arr::<2>()?);
        let mut out = Vec::with_capacity(usize::from(len));
        for _ in 0..len {
            out.push(self.take_arr::<32>()?);
        }
        Ok(out)
    }
    fn expect_end(&self) -> Result<(), MnemeError> {
        if self.pos != self.buf.len() {
            return Err(MnemeError::SchemaDrift);
        }
        Ok(())
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) -> Result<(), MnemeError> {
    let b = s.as_bytes();
    let len: u16 = b.len().try_into().map_err(|_| MnemeError::SchemaDrift)?;
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(b);
    Ok(())
}

fn put_id_list(out: &mut Vec<u8>, ids: &[[u8; 32]]) -> Result<(), MnemeError> {
    let len: u16 = ids.len().try_into().map_err(|_| MnemeError::SchemaDrift)?;
    out.extend_from_slice(&len.to_le_bytes());
    for id in ids {
        out.extend_from_slice(id);
    }
    Ok(())
}

pub fn mint_robr_receipt(
    operator: &KeyPair,
    root: &mneme_core::Root,
    prompt: &str,
    weight_measurement: [u8; 32],
    sampling: String,
    context: &[([u8; 32], Vec<u8>)],
    output_commit: [u8; 32],
) -> Result<Vec<u8>, MnemeError> {
    let ctx_hash = context_hash(context);
    let env = envelope_hash(
        &root.preimage_hash,
        blake3::hash(prompt.as_bytes()).as_bytes(),
        &weight_measurement,
        &sampling,
        &ctx_hash,
    );
    let receipt = RobrReceiptV1 {
        root_seq: root.sequence,
        root_preimage: root.preimage_hash,
        prompt_hash: *blake3::hash(prompt.as_bytes()).as_bytes(),
        weight_measurement,
        sampling_params: sampling,
        context_ids: context.iter().map(|(id, _)| *id).collect(),
        context_hash: ctx_hash,
        envelope_hash: env,
        output_token_commit: output_commit,
        operator_pk: operator.public_key_bytes(),
        sig: [0u8; 64],
    };
    receipt.sign_and_encode(operator)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(operator: &KeyPair) -> RobrReceiptV1 {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        let ctx = vec![(a, b"alpha".to_vec()), (b, b"beta".to_vec())];
        let ch = context_hash(&ctx);
        let root_preimage = [0xab; 32];
        let prompt_hash = *blake3::hash(b"what is the launch date?").as_bytes();
        let weight_measurement = [0xcd; 32];
        let sampling = "model=claude-opus-4-8;temp=0;top_p=1;seed=42".to_string();
        let env = envelope_hash(
            &root_preimage,
            &prompt_hash,
            &weight_measurement,
            &sampling,
            &ch,
        );
        RobrReceiptV1 {
            root_seq: 9,
            root_preimage,
            prompt_hash,
            weight_measurement,
            sampling_params: sampling,
            context_ids: vec![a, b],
            context_hash: ch,
            envelope_hash: env,
            output_token_commit: *blake3::hash(b"the launch date is 2026-08-02").as_bytes(),
            operator_pk: operator.public_key_bytes(),
            sig: [0; 64],
        }
    }

    #[test]
    fn roundtrip_sign_verify() {
        let op = KeyPair::from_seed([9u8; 32]);
        let wire = sample(&op).sign_and_encode(&op).expect("encode");
        let r = RobrReceiptV1::verify(&wire, Some(&op.public_key_bytes())).expect("verify clean");
        assert_eq!(r.root_seq, 9);
        assert_eq!(r.context_ids.len(), 2);
    }

    #[test]
    fn every_byte_flip_fails_closed() {
        let op = KeyPair::from_seed([9u8; 32]);
        let wire = sample(&op).sign_and_encode(&op).expect("encode");
        for i in 0..wire.len() {
            let mut bad = wire.clone();
            bad[i] ^= 0x01;
            assert!(
                RobrReceiptV1::verify(&bad, Some(&op.public_key_bytes())).is_err(),
                "byte flip at {i} must fail closed"
            );
        }
    }

    #[test]
    fn truncation_and_trailing_fail_closed() {
        let op = KeyPair::from_seed([9u8; 32]);
        let wire = sample(&op).sign_and_encode(&op).expect("encode");
        assert!(RobrReceiptV1::verify(&wire[..wire.len() - 1], None).is_err());
        let mut extra = wire.clone();
        extra.push(0);
        assert!(RobrReceiptV1::verify(&extra, None).is_err());
    }

    #[test]
    fn wrong_pinned_pk_rejected() {
        let op = KeyPair::from_seed([9u8; 32]);
        let other = KeyPair::from_seed([8u8; 32]);
        let wire = sample(&op).sign_and_encode(&op).expect("encode");
        assert!(matches!(
            RobrReceiptV1::verify(&wire, Some(&other.public_key_bytes())),
            Err(MnemeError::RootSigInvalid)
        ));
    }

    #[test]
    fn envelope_not_matching_inputs_rejected_even_if_signed() {
        // A receipt whose envelope does not bind its declared inputs is rejected, even
        // when the signature is valid — this is the core ROBR-1 guarantee.
        let op = KeyPair::from_seed([9u8; 32]);
        let mut c = sample(&op);
        c.envelope_hash = [0u8; 32]; // does not equal H(root‖prompt‖weights‖sampling‖ctx)
        let wire = c.sign_and_encode(&op).expect("encode");
        assert!(matches!(
            RobrReceiptV1::verify(&wire, None),
            Err(MnemeError::SchemaDrift)
        ));
    }

    // Deterministic xorshift so the generative suite is reproducible without rand.
    fn xorshift(state: &mut u64) -> u64 {
        let mut x = *state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        *state = x;
        x
    }

    fn arr32(state: &mut u64) -> [u8; 32] {
        let mut a = [0u8; 32];
        for chunk in a.chunks_mut(8) {
            chunk.copy_from_slice(&xorshift(state).to_le_bytes()[..chunk.len()]);
        }
        a
    }

    #[test]
    fn generative_tamper_suite_200_cases_zero_forgeries() {
        // ≥150 randomized receipts; for each, the clean wire verifies and a mutated
        // wire (random byte flipped) fails closed. Zero forgeries permitted.
        let mut st: u64 = 0x9E3779B97F4A7C15;
        let cases = 200;
        for case in 0..cases {
            let op = KeyPair::from_seed(arr32(&mut st));
            let n_ctx = (xorshift(&mut st) % 5) as usize;
            let ctx: Vec<([u8; 32], Vec<u8>)> = (0..n_ctx)
                .map(|_| {
                    let id = arr32(&mut st);
                    let blen = (xorshift(&mut st) % 24) as usize;
                    let body: Vec<u8> = (0..blen)
                        .map(|_| (xorshift(&mut st) & 0xff) as u8)
                        .collect();
                    (id, body)
                })
                .collect();
            let root_preimage = arr32(&mut st);
            let prompt_hash = arr32(&mut st);
            let weight_measurement = arr32(&mut st);
            let sampling = format!("model=m{};seed={}", case, xorshift(&mut st) & 0xffff);
            let ch = context_hash(&ctx);
            let env = envelope_hash(
                &root_preimage,
                &prompt_hash,
                &weight_measurement,
                &sampling,
                &ch,
            );
            let receipt = RobrReceiptV1 {
                root_seq: xorshift(&mut st),
                root_preimage,
                prompt_hash,
                weight_measurement,
                sampling_params: sampling,
                context_ids: ctx.iter().map(|(id, _)| *id).collect(),
                context_hash: ch,
                envelope_hash: env,
                output_token_commit: arr32(&mut st),
                operator_pk: op.public_key_bytes(),
                sig: [0; 64],
            };
            let wire = receipt.sign_and_encode(&op).expect("encode");
            // Clean wire must verify.
            assert!(
                RobrReceiptV1::verify(&wire, Some(&op.public_key_bytes())).is_ok(),
                "case {case}: clean receipt must verify"
            );
            // A flipped byte at a pseudo-random position must fail closed.
            let pos = (xorshift(&mut st) as usize) % wire.len();
            let mut bad = wire.clone();
            bad[pos] ^= 1 + (xorshift(&mut st) & 0x7f) as u8;
            assert!(
                RobrReceiptV1::verify(&bad, Some(&op.public_key_bytes())).is_err(),
                "case {case}: tampered receipt (byte {pos}) must fail closed"
            );
        }
    }

    #[test]
    fn changing_a_bound_input_breaks_the_envelope() {
        // Flipping the prompt after the fact (keeping the old envelope) must not verify:
        // re-sign with a mutated prompt but stale envelope → inconsistent → rejected.
        let op = KeyPair::from_seed([9u8; 32]);
        let mut c = sample(&op);
        c.prompt_hash = *blake3::hash(b"a different prompt").as_bytes();
        let wire = c.sign_and_encode(&op).expect("encode");
        assert!(RobrReceiptV1::verify(&wire, None).is_err());
    }

    // ----- ROBR-2 reference kernel + replay -----

    #[test]
    fn reference_kernel_is_deterministic_and_envelope_sensitive() {
        let e1 = [0x11u8; 32];
        let e2 = [0x12u8; 32];
        assert_eq!(
            reference_kernel(&e1),
            reference_kernel(&e1),
            "same envelope must reproduce the same output bit-for-bit"
        );
        assert_ne!(
            reference_kernel(&e1),
            reference_kernel(&e2),
            "different envelopes must produce different output"
        );
    }

    /// Build a replay-verifiable receipt: output is generated BY the reference kernel,
    /// so re-execution reproduces the committed output exactly.
    fn replayable_sample(operator: &KeyPair) -> RobrReceiptV1 {
        let mut c = sample(operator);
        c.output_token_commit = commit_output(&reference_kernel(&c.envelope_hash));
        c
    }

    #[test]
    fn replay_accepts_reference_kernel_output() {
        let op = KeyPair::from_seed([9u8; 32]);
        let wire = replayable_sample(&op).sign_and_encode(&op).expect("encode");
        let r = RobrReceiptV1::verify(&wire, Some(&op.public_key_bytes())).expect("verify");
        assert!(
            replay_reproduces_output(&r),
            "a receipt whose output came from the reference kernel must replay-verify"
        );
    }

    #[test]
    fn replay_rejects_output_not_from_reference_kernel() {
        // The default `sample` commits an arbitrary output (as if from some other
        // producer); replay against the reference kernel must NOT match.
        let op = KeyPair::from_seed([9u8; 32]);
        let r = sample(&op);
        assert!(
            !replay_reproduces_output(&r),
            "an output that is not the reference kernel's must fail replay"
        );
    }

    #[test]
    fn replay_fails_if_envelope_inputs_differ() {
        // Same output commitment, but a different envelope (e.g. different prompt) →
        // the reference kernel produces a different stream → replay fails. Binds the
        // output to the EXACT committed inputs.
        let op = KeyPair::from_seed([9u8; 32]);
        let mut c = replayable_sample(&op);
        // Tamper an input the envelope binds; envelope_hash recomputed to stay
        // internally consistent, but now the committed output no longer matches.
        c.prompt_hash = *blake3::hash(b"different prompt").as_bytes();
        c.envelope_hash = envelope_hash(
            &c.root_preimage,
            &c.prompt_hash,
            &c.weight_measurement,
            &c.sampling_params,
            &c.context_hash,
        );
        assert!(
            !replay_reproduces_output(&c),
            "changing a bound input must break replay even with a consistent envelope"
        );
    }

    #[test]
    fn mint_robr_receipt_roundtrips_through_verify() {
        // The store-kernel mint path (`mint_robr_receipt`) produces a wire that verifies
        // and whose carried fields match the inputs.
        let op = KeyPair::from_seed([7u8; 32]);
        let root = mneme_core::Root {
            version: 1,
            preimage_hash: [0x33; 32],
            dag_head_root: [0; 32],
            key_index_root: [0; 32],
            semantic_commit: [0; 32],
            hlc_max: [0; 14],
            prev_root: [0; 32],
            signature: Vec::new(),
            sequence: 5,
        };
        let ctx = vec![([0x44u8; 32], b"ctx body".to_vec())];
        let output_commit = *blake3::hash(b"out").as_bytes();
        let wire = mint_robr_receipt(
            &op,
            &root,
            "the prompt",
            [0x99; 32],
            "model=x;temp=0".to_string(),
            &ctx,
            output_commit,
        )
        .expect("mint");
        let r = RobrReceiptV1::verify(&wire, Some(&op.public_key_bytes())).expect("verify");
        assert_eq!(r.root_seq, 5);
        assert_eq!(r.root_preimage, [0x33; 32]);
        assert_eq!(r.output_token_commit, output_commit);
        assert_eq!(r.prompt_hash, *blake3::hash(b"the prompt").as_bytes());
    }

    /// Regenerates the committed cross-implementation vectors under `proof/vectors/`.
    /// Ignored in normal runs (it writes into the source tree and assumes CWD = crate
    /// dir); run with `cargo test -p mneme-account -- --ignored generate_crossref_vectors`
    /// when the wire format changes. The committed vectors are independently re-verified
    /// by `mneme-crossref` (which imports no `mneme-*` crate).
    #[test]
    #[ignore = "writes vectors into the source tree; run explicitly to regenerate"]
    fn generate_crossref_vectors() {
        let operator = KeyPair::from_seed([9u8; 32]);
        let pk = operator.public_key_bytes();

        // 1. Generate ROBR Receipt Vector
        let context_entry_id = [0x11u8; 32];
        let context_entry_body = b"hello crossref".to_vec();
        let ctx = vec![(context_entry_id, context_entry_body)];
        let ctx_hash = context_hash(&ctx);
        let root_preimage = [0xab; 32];
        let prompt_hash = *blake3::hash(b"test prompt").as_bytes();
        let weight_measurement = [0xcd; 32];
        let sampling = "model=crossref-v1;temp=0".to_string();
        let env = envelope_hash(
            &root_preimage,
            &prompt_hash,
            &weight_measurement,
            &sampling,
            &ctx_hash,
        );
        let robr_receipt = RobrReceiptV1 {
            root_seq: 42,
            root_preimage,
            prompt_hash,
            weight_measurement,
            sampling_params: sampling,
            context_ids: vec![context_entry_id],
            context_hash: ctx_hash,
            envelope_hash: env,
            output_token_commit: *blake3::hash(b"test output").as_bytes(),
            operator_pk: pk,
            sig: [0; 64],
        };
        let robr_bytes = robr_receipt.sign_and_encode(&operator).unwrap();
        std::fs::write("../../proof/vectors/robr_vector_v1.bin", &robr_bytes).unwrap();

        // 2. Generate PaceLog Vector
        let cal = mneme_pace::PaceCalibration {
            alg: mneme_pace::PACE_ALG_BLAKE3_SEQUENTIAL,
            iterations_per_tick: 10,
            tick_target_ms: 1,
        };
        let mut log = mneme_pace::create_log(pk, cal).unwrap();
        mneme_pace::append_segment(&mut log, 10, Some("root-seq-42".to_string())).unwrap();
        let log_bytes = mneme_pace::save_log(&log).unwrap();
        std::fs::write("../../proof/vectors/pace_log_vector_v1.cbor", &log_bytes).unwrap();

        // 3. Generate ForgetProof Vector
        let fp = mneme_core::ForgetProof {
            version: mneme_core::FORGET_PROOF_VERSION,
            target_commit: [0x55; 32],
            mode: mneme_core::ForgetMode::Shred,
            shred_commit: [0x66; 32],
            absence_path: vec![[0x77; 32]; 256],
            root_bound: [0x88; 32],
            cognition_cert_commit: None,
        };
        let fp_bytes = mneme_core::encode_forget_proof(&fp).unwrap();
        std::fs::write("../../proof/vectors/forget_proof_vector_v1.cbor", &fp_bytes).unwrap();
    }
}

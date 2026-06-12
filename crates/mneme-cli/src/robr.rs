//! ROBR — Recall-to-Output Binding Receipt (capability 1, task ROBR-1: the envelope).
//!
//! `mneme robr receipt` emits a signed, offline-verifiable envelope that binds a model
//! output commitment to the EXACT inputs that produced it:
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
//! Wire: deterministic length-prefixed v1 layout reusing the strict fail-closed reader
//! from [`crate::replay`] (unknown version, length mismatch, or trailing bytes ⇒ typed
//! error). The signature covers the full payload.

use crate::replay::{Reader, put_id_list, put_str};
use mneme_core::MnemeError;
use mneme_crypto::{KeyPair, sign_message, verify_signature_bytes, verifying_key_from_bytes};

pub const ROBR_RECEIPT_VERSION: u16 = 1;
const PAYLOAD_DOMAIN: &[u8] = b"MNEME-robr-receipt-v1";
const ENVELOPE_DOMAIN: &[u8] = b"MNEME-robr-envelope-v1";
const CONTEXT_DOMAIN: &[u8] = b"MNEME-robr-context-v1";

pub const ROBR_HONESTY: &str = "binding receipt only: cryptographically binds the output \
commitment to this signed memory root, prompt, operator-asserted weight measurement, sampling \
params, and verified context; it does NOT prove the model produced the output (that needs \
ROBR-2 replay or ROBR-4 TEE attestation) and never proves semantic truth — authenticated != true";

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

/// Chained context hash over (id, body) pairs in recall order. Distinct domain tag
/// from CCR so a context hash from one protocol can never be replayed as the other.
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

/// The binding envelope. This is the load-bearing relation ROBR asserts: the output
/// commitment is bound to exactly these inputs. Any change to root, prompt, weights,
/// sampling, or context changes the envelope and the receipt no longer verifies.
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
    ///
    /// `pinned_pk`: optional out-of-band operator public key; if provided it must match
    /// the embedded key.
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

        // Internal consistency: the carried envelope MUST equal the envelope recomputed
        // from the bound inputs. A signed-but-inconsistent receipt (e.g. envelope that
        // does not match the declared root/prompt/weights/sampling/context) is rejected.
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
}

//! Offline-verifiable capability tokens with trust-tier model (blueprint §12, §13.4).

mod wire;

use mneme_core::{Hlc, MemoryKind, MnemeError, NodeId, TrustTier, hash_cap, to_bytes_canonical};
use mneme_crypto::{KeyPair, PublicKeyBytes, public_key_from_bytes, verify_signature};
use std::ops::{Deref, DerefMut};
use wire::{decode_capability, encode_capability};

pub use mneme_core::Caveat;
pub use wire::{CapPreimage, fuzz_decode_capability};

pub const SIG_LEN: usize = 64;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Permissions: u8 {
        const READ    = 0b0000_0001;
        const WRITE   = 0b0000_0010;
        const FORGET  = 0b0000_0100;
        const MERGE   = 0b0000_1000;
        const PROMOTE = 0b0001_0000;
    }
}

/// Store-facing wrapper around the frozen `mneme-core` capability seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    inner: mneme_core::Capability,
}

impl Deref for Capability {
    type Target = mneme_core::Capability;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Capability {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Capability {
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        issuer: &KeyPair,
        subject: PublicKeyBytes,
        namespaces: Vec<String>,
        kinds: Vec<MemoryKind>,
        tier_max: TrustTier,
        tier_default: TrustTier,
        permissions: Permissions,
        caveats: Vec<Caveat>,
    ) -> Result<Self, MnemeError> {
        let cap = mneme_core::Capability {
            issuer: issuer.public_key_bytes(),
            subject,
            namespaces,
            kinds: kinds.iter().map(|k| k.as_u8()).collect(),
            tier_max: tier_max.as_u8(),
            tier_default: tier_default.as_u8(),
            permissions: permissions.bits(),
            caveats,
            signature: Vec::new(),
        };
        Self::from_core(cap).sign_root(issuer)
    }

    pub fn from_core(inner: mneme_core::Capability) -> Self {
        Self { inner }
    }

    pub fn into_core(self) -> mneme_core::Capability {
        self.inner
    }

    pub fn inner(&self) -> &mneme_core::Capability {
        &self.inner
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MnemeError> {
        Ok(Self {
            inner: decode_capability(bytes)?,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, MnemeError> {
        encode_capability(&self.inner)
    }

    fn sign_root(self, issuer: &KeyPair) -> Result<Self, MnemeError> {
        let cap_id = self.cap_id()?;
        let sig = issuer.sign(&cap_id);
        Ok(Self {
            inner: mneme_core::Capability {
                signature: sig.to_vec(),
                ..self.inner
            },
        })
    }

    fn sign_attenuation(self, subject: &KeyPair) -> Result<Self, MnemeError> {
        let cap_id = self.cap_id()?;
        let sig = subject.sign(&cap_id);
        let mut chain = self.inner.signature.clone();
        chain.extend_from_slice(&sig);
        Ok(Self {
            inner: mneme_core::Capability {
                signature: chain,
                ..self.inner
            },
        })
    }

    fn verify_sig_chain(&self) -> Result<(), MnemeError> {
        let chain = parse_sig_chain(&self.inner.signature)?;
        let issuer_pk =
            public_key_from_bytes(&self.inner.issuer).map_err(|_| MnemeError::CapMalformed)?;
        let subject_pk =
            public_key_from_bytes(&self.inner.subject).map_err(|_| MnemeError::CapMalformed)?;

        for (i, sig) in chain.iter().enumerate() {
            let caveat_count = self
                .inner
                .caveats
                .len()
                .saturating_sub(chain.len() - 1)
                .saturating_add(i);
            let cap_id = self.cap_id_for_caveats(caveat_count)?;
            let pk = if i == 0 { &issuer_pk } else { &subject_pk };
            verify_signature(pk, &cap_id, sig).map_err(map_sig_err)?;
        }
        Ok(())
    }

    fn cap_id_for_caveats(&self, caveat_count: usize) -> Result<[u8; 32], MnemeError> {
        let mut preimage = CapPreimage::from(&self.inner);
        preimage.caveats.truncate(caveat_count);
        let canonical = to_bytes_canonical(&preimage)?;
        Ok(hash_cap(&canonical))
    }

    fn evaluate_time_caveats(&self, now: &Hlc) -> Result<(), MnemeError> {
        for caveat in &self.inner.caveats {
            match caveat {
                Caveat::NotAfter(limit) | Caveat::CreatedBefore(limit) => {
                    if !now.is_before(limit) {
                        return Err(MnemeError::CapExpired);
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn cap_id(&self) -> Result<[u8; 32], MnemeError> {
        self.cap_id_for_caveats(self.inner.caveats.len())
    }

    pub fn attenuate(&self, subject: &KeyPair, extra: Vec<Caveat>) -> Result<Self, MnemeError> {
        if subject.public_key_bytes() != self.inner.subject {
            return Err(MnemeError::CapDenied);
        }
        let mut narrowed = self.clone();
        for caveat in extra {
            if !caveat_narrows(&caveat) {
                return Err(MnemeError::CapDenied);
            }
            narrowed.inner.caveats.push(caveat);
        }
        narrowed.sign_attenuation(subject)
    }

    pub fn verify(&self, issuer: &KeyPair, now: &Hlc) -> Result<(), MnemeError> {
        if self.inner.issuer != issuer.public_key_bytes() {
            return Err(MnemeError::CapDenied);
        }
        self.verify_sig_chain()?;
        self.evaluate_time_caveats(now)?;
        Ok(())
    }

    pub fn verify_issuer_chain(&self, issuer: &KeyPair) -> Result<(), MnemeError> {
        if self.inner.issuer != issuer.public_key_bytes() {
            return Err(MnemeError::CapDenied);
        }
        self.verify_sig_chain()
    }

    pub fn sig_chain(&self) -> Result<Vec<[u8; SIG_LEN]>, MnemeError> {
        parse_sig_chain(&self.inner.signature)
    }

    pub fn permits_write(&self, namespace: &str, kind: MemoryKind) -> bool {
        self.inner.permissions & Permissions::WRITE.bits() != 0
            && namespace_allowed(&self.inner.namespaces, &self.inner.caveats, namespace)
            && kind_allowed(&self.inner.kinds, &self.inner.caveats, kind)
    }

    pub fn permits_read(&self, namespace: &str, min_tier: TrustTier) -> bool {
        self.inner.permissions & Permissions::READ.bits() != 0
            && namespace_allowed(&self.inner.namespaces, &self.inner.caveats, namespace)
            && min_tier.as_u8() <= self.inner.tier_max
    }

    pub fn permits_forget(&self) -> bool {
        self.inner.permissions & Permissions::FORGET.bits() != 0
    }

    pub fn permits_promote(&self) -> bool {
        self.inner.permissions & Permissions::PROMOTE.bits() != 0
    }

    pub fn require_promote(&self) -> Result<(), MnemeError> {
        if self.permits_promote() {
            Ok(())
        } else {
            Err(MnemeError::PromoteDenied)
        }
    }

    pub fn default_tier(&self) -> TrustTier {
        TrustTier::from_u8(self.inner.tier_default).unwrap_or(TrustTier::Quarantine)
    }

    pub fn writer_hash(&self) -> [u8; 32] {
        use blake3::Hasher;
        let mut h = Hasher::new();
        h.update(&self.inner.subject);
        *h.finalize().as_bytes()
    }
}

pub fn default_cap_expiry() -> Hlc {
    Hlc {
        wall_ms: u64::MAX / 4,
        counter: 0,
        node_id: NodeId([0x00; 16]),
    }
}

pub fn tool_channel_cap(
    issuer: &KeyPair,
    subject: PublicKeyBytes,
) -> Result<Capability, MnemeError> {
    tool_channel_cap_with_expiry(issuer, subject, default_cap_expiry())
}

pub fn tool_channel_cap_with_expiry(
    issuer: &KeyPair,
    subject: PublicKeyBytes,
    not_after: Hlc,
) -> Result<Capability, MnemeError> {
    Capability::issue(
        issuer,
        subject,
        vec!["tools".into()],
        vec![
            MemoryKind::Episodic,
            MemoryKind::Semantic,
            MemoryKind::Procedural,
            MemoryKind::Working,
        ],
        TrustTier::Quarantine,
        TrustTier::Quarantine,
        Permissions::READ | Permissions::WRITE,
        vec![
            Caveat::NotAfter(not_after),
            Caveat::NamespacePrefix("tools".into()),
        ],
    )
}

pub fn agent_cap(issuer: &KeyPair, subject: PublicKeyBytes) -> Result<Capability, MnemeError> {
    agent_cap_with_expiry(issuer, subject, default_cap_expiry())
}

pub fn agent_cap_with_expiry(
    issuer: &KeyPair,
    subject: PublicKeyBytes,
    not_after: Hlc,
) -> Result<Capability, MnemeError> {
    Capability::issue(
        issuer,
        subject,
        vec!["*".into()],
        vec![
            MemoryKind::Episodic,
            MemoryKind::Semantic,
            MemoryKind::Procedural,
            MemoryKind::Working,
            MemoryKind::Identity,
        ],
        TrustTier::Identity,
        TrustTier::Identity,
        Permissions::READ | Permissions::WRITE | Permissions::FORGET | Permissions::PROMOTE,
        vec![Caveat::NotAfter(not_after)],
    )
}

fn parse_sig_chain(bytes: &[u8]) -> Result<Vec<[u8; SIG_LEN]>, MnemeError> {
    if bytes.is_empty() || bytes.len() % SIG_LEN != 0 {
        return Err(MnemeError::CapMalformed);
    }
    bytes
        .chunks_exact(SIG_LEN)
        .map(|chunk| chunk.try_into().map_err(|_| MnemeError::CapMalformed))
        .collect()
}

fn map_sig_err(err: MnemeError) -> MnemeError {
    match err {
        MnemeError::RootSigInvalid => MnemeError::CapDenied,
        other => other,
    }
}

fn namespace_allowed(namespaces: &[String], caveats: &[Caveat], namespace: &str) -> bool {
    let prefix_ok = caveats.iter().all(|c| match c {
        Caveat::NamespacePrefix(prefix) => namespace.starts_with(prefix.as_str()),
        _ => true,
    });
    if !prefix_ok {
        return false;
    }
    namespaces.iter().any(|ns| {
        ns == namespace
            || (ns == "*" && !namespace.is_empty())
            || namespace.starts_with(ns.as_str())
    })
}

fn kind_allowed(kinds: &[u8], caveats: &[Caveat], kind: MemoryKind) -> bool {
    let caveat_ok = caveats.iter().all(|c| match c {
        Caveat::OnlyEpisodic => kind == MemoryKind::Episodic,
        _ => true,
    });
    caveat_ok && kinds.contains(&kind.as_u8())
}

fn caveat_narrows(caveat: &Caveat) -> bool {
    matches!(
        caveat,
        Caveat::NotAfter(_)
            | Caveat::CreatedBefore(_)
            | Caveat::OnlyEpisodic
            | Caveat::NamespacePrefix(_)
            | Caveat::RateLimited(_)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_hlc(wall_ms: u64) -> Hlc {
        Hlc {
            wall_ms,
            counter: 0,
            node_id: NodeId([0x01; 16]),
        }
    }

    fn far_future() -> Hlc {
        test_hlc(u64::MAX / 2)
    }

    #[test]
    fn cap_issue_verify_roundtrip() {
        let issuer = KeyPair::from_seed([0x11; 32]);
        let subject = KeyPair::from_seed([0x22; 32]);
        let cap = Capability::issue(
            &issuer,
            subject.public_key_bytes(),
            vec!["agent".into()],
            vec![MemoryKind::Semantic],
            TrustTier::Trusted,
            TrustTier::Working,
            Permissions::READ | Permissions::WRITE,
            vec![Caveat::NotAfter(far_future())],
        )
        .unwrap();
        cap.verify(&issuer, &test_hlc(100)).unwrap();
        let bytes = cap.to_bytes().unwrap();
        let decoded = Capability::from_bytes(&bytes).unwrap();
        decoded.verify(&issuer, &test_hlc(100)).unwrap();
    }

    #[test]
    fn tool_channel_quarantine_no_promote() {
        let issuer = KeyPair::from_seed([0x33; 32]);
        let subject = KeyPair::from_seed([0x44; 32]);
        let cap = tool_channel_cap(&issuer, subject.public_key_bytes()).unwrap();
        assert_eq!(cap.default_tier(), TrustTier::Quarantine);
        assert!(!cap.permits_promote());
        assert_eq!(
            cap.require_promote().unwrap_err(),
            MnemeError::PromoteDenied
        );
        assert!(cap.permits_write("tools/mcp", MemoryKind::Semantic));
        assert!(!cap.permits_write("agent/x", MemoryKind::Semantic));
    }

    #[test]
    fn not_after_expired_returns_cap_expired() {
        let issuer = KeyPair::from_seed([0x55; 32]);
        let subject = KeyPair::from_seed([0x66; 32]);
        let cap = Capability::issue(
            &issuer,
            subject.public_key_bytes(),
            vec!["*".into()],
            vec![MemoryKind::Working],
            TrustTier::Working,
            TrustTier::Working,
            Permissions::READ,
            vec![Caveat::NotAfter(test_hlc(50))],
        )
        .unwrap();
        assert_eq!(
            cap.verify(&issuer, &test_hlc(50)).unwrap_err(),
            MnemeError::CapExpired
        );
        assert_eq!(
            cap.verify(&issuer, &test_hlc(100)).unwrap_err(),
            MnemeError::CapExpired
        );
    }

    #[test]
    fn sig_chain_tamper_returns_cap_denied() {
        let issuer = KeyPair::from_seed([0x77; 32]);
        let subject = KeyPair::from_seed([0x88; 32]);
        let mut cap = agent_cap(&issuer, subject.public_key_bytes()).unwrap();
        cap.signature[0] ^= 0x01;
        assert_eq!(
            cap.verify(&issuer, &test_hlc(1)).unwrap_err(),
            MnemeError::CapDenied
        );
    }

    #[test]
    fn dcbor_sig_chain_byte_tamper_rejected() {
        let issuer = KeyPair::from_seed([0x99; 32]);
        let subject = KeyPair::from_seed([0xaa; 32]);
        let cap = agent_cap(&issuer, subject.public_key_bytes()).unwrap();
        let mut tampered = cap.clone();
        let idx = 32.min(tampered.signature.len().saturating_sub(1));
        tampered.signature[idx] ^= 0x01;
        assert_eq!(
            tampered.verify(&issuer, &test_hlc(1)).unwrap_err(),
            MnemeError::CapDenied
        );
    }

    #[test]
    fn attenuation_appends_subject_sig() {
        let issuer = KeyPair::from_seed([0xbb; 32]);
        let subject = KeyPair::from_seed([0xcc; 32]);
        let root = agent_cap(&issuer, subject.public_key_bytes()).unwrap();
        let narrowed = root
            .attenuate(&subject, vec![Caveat::NamespacePrefix("tools/".into())])
            .unwrap();
        assert_eq!(root.sig_chain().unwrap().len(), 1);
        assert_eq!(narrowed.sig_chain().unwrap().len(), 2);
        narrowed.verify(&issuer, &test_hlc(1)).unwrap();
    }

    #[test]
    fn sig_chain_malformed_length_is_cap_malformed() {
        let issuer = KeyPair::from_seed([0xdd; 32]);
        let subject = KeyPair::from_seed([0xee; 32]);
        let mut cap = agent_cap(&issuer, subject.public_key_bytes()).unwrap();
        cap.signature.truncate(10);
        assert_eq!(
            cap.verify(&issuer, &test_hlc(1)).unwrap_err(),
            MnemeError::CapMalformed
        );
    }
}

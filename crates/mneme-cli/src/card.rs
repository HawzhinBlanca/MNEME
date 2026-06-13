//! A2A (agent-to-agent) discovery seed — a JWS-signed Agent Card (MTL-2 seed).
//!
//! HONESTY BOUNDARY (do not weaken): the card is an Ed25519/JWS-signed assertion that
//! "the holder of operator key `iss` advertises this attestation endpoint." It proves
//! key-authenticated provenance of the advertisement only. It does NOT prove the
//! endpoint is reachable, honest, or itself attested, and an unpinned verify trusts the
//! self-asserted embedded key — confirm the operator key out-of-band. authenticated != true.

use base64::Engine;
use mneme_core::MnemeError;
use mneme_crypto::{KeyPair, verify_signature_bytes, verifying_key_from_bytes};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

pub const AGENT_CARD_HONESTY: &str = "JWS-signed advertisement only: proves the operator \
key signed this attestation-endpoint claim; it does NOT prove the endpoint is reachable, \
honest, or attested, and an unpinned verify trusts the self-asserted embedded key — \
authenticated != true";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AgentCardPayload {
    pub iss: String,
    pub sub: String,
    pub attestation_endpoint: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct JwsHeader {
    alg: String,
    typ: String,
}

pub fn generate_agent_card(
    operator: &KeyPair,
    attestation_endpoint: &str,
) -> Result<String, MnemeError> {
    let header = JwsHeader {
        alg: "EdDSA".to_string(),
        typ: "JWT".to_string(),
    };
    let header_json = serde_json::to_string(&header).map_err(|_| MnemeError::CapMalformed)?;
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MnemeError::CapMalformed)?
        .as_secs();

    let payload = AgentCardPayload {
        iss: hex::encode(operator.public_key_bytes()),
        sub: "mneme-agent".to_string(),
        attestation_endpoint: attestation_endpoint.to_string(),
        iat: now,
        exp: now + 31536000, // 1 year
    };
    let payload_json = serde_json::to_string(&payload).map_err(|_| MnemeError::CapMalformed)?;
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

    let signing_input = format!("{header_b64}.{payload_b64}");
    let sig = operator.sign(signing_input.as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

    Ok(format!("{signing_input}.{sig_b64}"))
}

pub fn verify_agent_card(
    card_str: &str,
    operator_pk: Option<&[u8; 32]>,
) -> Result<AgentCardPayload, MnemeError> {
    let parts: Vec<&str> = card_str.split('.').collect();
    if parts.len() != 3 {
        return Err(MnemeError::RootSigInvalid);
    }

    let header_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0].as_bytes())
        .map_err(|_| MnemeError::RootSigInvalid)?;
    let header: JwsHeader =
        serde_json::from_slice(&header_bytes).map_err(|_| MnemeError::RootSigInvalid)?;

    if header.alg != "EdDSA" || header.typ != "JWT" {
        return Err(MnemeError::RootSigInvalid);
    }

    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1].as_bytes())
        .map_err(|_| MnemeError::RootSigInvalid)?;
    let payload: AgentCardPayload =
        serde_json::from_slice(&payload_bytes).map_err(|_| MnemeError::RootSigInvalid)?;

    let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2].as_bytes())
        .map_err(|_| MnemeError::RootSigInvalid)?;

    let iss_bytes = hex::decode(&payload.iss).map_err(|_| MnemeError::RootSigInvalid)?;
    let iss_pk: [u8; 32] = iss_bytes
        .try_into()
        .map_err(|_| MnemeError::RootSigInvalid)?;

    if let Some(pinned) = operator_pk {
        if &iss_pk != pinned {
            return Err(MnemeError::RootSigInvalid);
        }
    }

    if payload.sub != "mneme-agent" {
        return Err(MnemeError::RootSigInvalid);
    }

    if payload.exp <= payload.iat {
        return Err(MnemeError::RootSigInvalid);
    }

    let verifying_key = verifying_key_from_bytes(&iss_pk)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verify_signature_bytes(&verifying_key, signing_input.as_bytes(), &sig_bytes)?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| MnemeError::CapMalformed)?
        .as_secs();

    if now > payload.exp {
        return Err(MnemeError::RootSigInvalid);
    }

    // Allow up to 60 seconds of clock skew for future-dated issued-at time
    if now + 60 < payload.iat {
        return Err(MnemeError::RootSigInvalid);
    }

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_agent_card() {
        let op = KeyPair::from_seed([3u8; 32]);
        let card = generate_agent_card(&op, "http://localhost/attest").unwrap();
        let payload = verify_agent_card(&card, Some(&op.public_key_bytes())).unwrap();
        assert_eq!(payload.sub, "mneme-agent");
        assert_eq!(payload.attestation_endpoint, "http://localhost/attest");
    }

    #[test]
    fn test_wrong_sub_rejected() {
        let op = KeyPair::from_seed([3u8; 32]);
        let header = JwsHeader {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());

        let payload = AgentCardPayload {
            iss: hex::encode(op.public_key_bytes()),
            sub: "not-mneme-agent".to_string(),
            attestation_endpoint: "http://localhost/attest".to_string(),
            iat: 1000,
            exp: 2000,
        };
        let payload_json = serde_json::to_string(&payload).unwrap();
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = op.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

        let card = format!("{signing_input}.{sig_b64}");
        assert!(matches!(
            verify_agent_card(&card, None),
            Err(MnemeError::RootSigInvalid)
        ));
    }

    #[test]
    fn test_exp_le_iat_rejected() {
        let op = KeyPair::from_seed([3u8; 32]);
        let header = JwsHeader {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());

        let payload = AgentCardPayload {
            iss: hex::encode(op.public_key_bytes()),
            sub: "mneme-agent".to_string(),
            attestation_endpoint: "http://localhost/attest".to_string(),
            iat: 2000,
            exp: 1000,
        };
        let payload_json = serde_json::to_string(&payload).unwrap();
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = op.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

        let card = format!("{signing_input}.{sig_b64}");
        assert!(matches!(
            verify_agent_card(&card, None),
            Err(MnemeError::RootSigInvalid)
        ));
    }

    #[test]
    fn test_future_dated_rejected() {
        let op = KeyPair::from_seed([3u8; 32]);
        let header = JwsHeader {
            alg: "EdDSA".to_string(),
            typ: "JWT".to_string(),
        };
        let header_json = serde_json::to_string(&header).unwrap();
        let header_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json.as_bytes());

        let payload = AgentCardPayload {
            iss: hex::encode(op.public_key_bytes()),
            sub: "mneme-agent".to_string(),
            attestation_endpoint: "http://localhost/attest".to_string(),
            iat: u32::MAX as u64,
            exp: (u32::MAX as u64) + 1000,
        };
        let payload_json = serde_json::to_string(&payload).unwrap();
        let payload_b64 =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_json.as_bytes());

        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig = op.sign(signing_input.as_bytes());
        let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig);

        let card = format!("{signing_input}.{sig_b64}");
        assert!(matches!(
            verify_agent_card(&card, None),
            Err(MnemeError::RootSigInvalid)
        ));
    }
}

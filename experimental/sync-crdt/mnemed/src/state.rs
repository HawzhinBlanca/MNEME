//! Shared server state and auth helpers.

use mneme_cap::Capability;
use mneme_core::MnemeError;
use mneme_crypto::KeyPair;
use mneme_store::Store;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type SharedStore = Arc<Mutex<Store>>;

#[derive(Clone)]
pub struct AppState {
    pub store: SharedStore,
    pub operator: Arc<KeyPair>,
    pub rate_limit: Arc<Mutex<RateLimiter>>,
}

#[derive(Default)]
pub struct RateLimiter {
    windows: HashMap<String, (u32, Instant)>,
    max_per_minute: u32,
}

impl RateLimiter {
    pub fn new(max_per_minute: u32) -> Self {
        Self {
            windows: HashMap::new(),
            max_per_minute,
        }
    }

    pub fn check(&mut self, key: &str) -> Result<(), MnemeError> {
        let now = Instant::now();
        let entry = self.windows.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) > Duration::from_secs(60) {
            *entry = (0, now);
        }
        if entry.0 >= self.max_per_minute {
            return Err(MnemeError::CapDenied);
        }
        entry.0 += 1;
        Ok(())
    }
}

pub fn parse_capability_b64(b64: &str) -> Result<Capability, ApiError> {
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64.trim())
        .map_err(|_| ApiError::bad_auth("invalid capability encoding"))?;
    Capability::from_bytes(&bytes).map_err(ApiError::from_mneme)
}

pub fn capability_from_header(value: &str) -> Result<Capability, ApiError> {
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
        .unwrap_or(value);
    parse_capability_b64(token)
}

pub fn verify_cap(state: &AppState, cap: &Capability) -> Result<(), ApiError> {
    let store = state
        .store
        .lock()
        .map_err(|_| ApiError::internal("store lock poisoned"))?;
    cap.verify(state.operator.as_ref(), store.current_hlc())
        .map_err(ApiError::from_mneme)
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: 400,
            code: "bad_request",
            message: msg.into(),
        }
    }

    pub fn bad_auth(msg: impl Into<String>) -> Self {
        Self {
            status: 401,
            code: "unauthorized",
            message: msg.into(),
        }
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: 403,
            code: "forbidden",
            message: msg.into(),
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: 404,
            code: "not_found",
            message: msg.into(),
        }
    }

    pub fn rate_limited() -> Self {
        Self {
            status: 429,
            code: "rate_limited",
            message: "rate limit exceeded".into(),
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: 500,
            code: "internal",
            message: msg.into(),
        }
    }

    pub fn from_mneme(err: MnemeError) -> Self {
        let (status, code) = match &err {
            MnemeError::CapDenied | MnemeError::CapExpired | MnemeError::CapMalformed => {
                (403, "cap_denied")
            }
            MnemeError::PromoteDenied => (403, "promote_denied"),
            MnemeError::BelowTierPolicy { .. } => (403, "below_tier"),
            MnemeError::IndexPathInvalid => (404, "not_found"),
            MnemeError::Forgotten => (410, "forgotten"),
            MnemeError::RootSigInvalid
            | MnemeError::RootInconsistent
            | MnemeError::RootReplayed
            | MnemeError::ReceiptRootMismatch
            | MnemeError::ObjectTampered
            | MnemeError::UnauthorizedWriter => (403, "verify_failed"),
            _ => (500, "kernel_error"),
        };
        Self {
            status,
            code,
            message: err.to_string(),
        }
    }
}

pub fn check_rate_limit(state: &AppState, cap: &Capability) -> Result<(), ApiError> {
    let key = hex::encode(cap.subject);
    state
        .rate_limit
        .lock()
        .map_err(|_| ApiError::internal("rate limiter poisoned"))?
        .check(&key)
        .map_err(|_| ApiError::rate_limited())
}

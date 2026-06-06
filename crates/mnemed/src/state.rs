//! Shared server state and auth helpers.

use mneme_cap::Capability;
use mneme_core::MnemeError;
use mneme_crypto::KeyPair;
use mneme_store::Store;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub type SharedStore = Arc<Mutex<Store>>;
pub const MAX_CAPABILITY_B64_LEN: usize = 4 * 1024;
pub const MAX_RATE_LIMIT_SUBJECT_WINDOWS: usize = 4096;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

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
        self.prune_expired_windows(now);
        if !self.windows.contains_key(key) && self.windows.len() >= MAX_RATE_LIMIT_SUBJECT_WINDOWS {
            return Err(MnemeError::CapDenied);
        }
        let entry = self.windows.entry(key.to_string()).or_insert((0, now));
        if now.duration_since(entry.1) > RATE_LIMIT_WINDOW {
            *entry = (0, now);
        }
        if entry.0 >= self.max_per_minute {
            return Err(MnemeError::CapDenied);
        }
        entry.0 += 1;
        Ok(())
    }

    fn prune_expired_windows(&mut self, now: Instant) {
        self.windows
            .retain(|_, (_, started_at)| now.duration_since(*started_at) <= RATE_LIMIT_WINDOW);
    }
}

pub fn parse_capability_b64(b64: &str) -> Result<Capability, ApiError> {
    let token = b64.trim();
    if token.len() > MAX_CAPABILITY_B64_LEN {
        return Err(ApiError::bad_auth("capability token too large"));
    }
    let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token)
        .map_err(|_| ApiError::bad_auth("invalid capability encoding"))?;
    Capability::from_bytes(&bytes).map_err(|_| ApiError::bad_auth("invalid capability encoding"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oversized_capability_rejected_before_decode() {
        let token = "A".repeat(MAX_CAPABILITY_B64_LEN + 1);
        let err = parse_capability_b64(&token).expect_err("oversized capability must fail");

        assert_eq!(err.status, 401);
        assert_eq!(err.message, "capability token too large");
    }

    #[test]
    fn rate_limiter_prunes_stale_subject_windows_on_check() {
        let mut limiter = RateLimiter::new(10);
        let stale_started = Instant::now() - Duration::from_secs(61);
        limiter
            .windows
            .insert("stale-a".to_string(), (1, stale_started));
        limiter
            .windows
            .insert("stale-b".to_string(), (1, stale_started));

        limiter.check("fresh").expect("fresh subject allowed");

        assert_eq!(limiter.windows.len(), 1);
        assert!(limiter.windows.contains_key("fresh"));
    }

    #[test]
    fn rate_limiter_preserves_live_subject_window_while_pruning_stale_ones() {
        let mut limiter = RateLimiter::new(1);
        let stale_started = Instant::now() - Duration::from_secs(61);
        limiter.check("live").expect("first live request allowed");
        limiter
            .windows
            .insert("stale".to_string(), (1, stale_started));

        let err = limiter
            .check("live")
            .expect_err("live subject remains limited");

        assert!(matches!(err, MnemeError::CapDenied));
        assert_eq!(limiter.windows.len(), 1);
        assert!(limiter.windows.contains_key("live"));
    }

    #[test]
    fn rate_limiter_rejects_new_subject_when_active_window_cap_is_full() {
        let mut limiter = RateLimiter::new(10);
        let now = Instant::now();
        for subject_index in 0..MAX_RATE_LIMIT_SUBJECT_WINDOWS {
            limiter
                .windows
                .insert(format!("subject-{subject_index}"), (1, now));
        }

        let err = limiter
            .check("overflow-subject")
            .expect_err("new subject must fail closed when active window cap is full");

        assert!(matches!(err, MnemeError::CapDenied));
        assert_eq!(limiter.windows.len(), MAX_RATE_LIMIT_SUBJECT_WINDOWS);
        assert!(!limiter.windows.contains_key("overflow-subject"));
    }

    #[test]
    fn rate_limiter_allows_existing_subject_when_active_window_cap_is_full() {
        let mut limiter = RateLimiter::new(10);
        let now = Instant::now();
        for subject_index in 0..MAX_RATE_LIMIT_SUBJECT_WINDOWS {
            limiter
                .windows
                .insert(format!("subject-{subject_index}"), (1, now));
        }

        limiter
            .check("subject-7")
            .expect("existing subject remains governed by its own window");

        assert_eq!(limiter.windows.len(), MAX_RATE_LIMIT_SUBJECT_WINDOWS);
        assert_eq!(limiter.windows["subject-7"].0, 2);
    }
}

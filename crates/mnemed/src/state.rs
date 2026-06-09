//! Shared server state and auth helpers.

use axum::http::StatusCode;
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
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "bad_request",
            message: msg.into(),
        }
    }

    pub fn bad_auth(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "unauthorized",
            message: msg.into(),
        }
    }

    pub fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            code: "forbidden",
            message: msg.into(),
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            code: "not_found",
            message: msg.into(),
        }
    }

    pub fn rate_limited() -> Self {
        Self {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "rate_limited",
            message: "rate limit exceeded".into(),
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: "internal",
            message: msg.into(),
        }
    }

    pub fn from_mneme(err: MnemeError) -> Self {
        let (status, code) = match &err {
            MnemeError::CapDenied | MnemeError::CapExpired | MnemeError::CapMalformed => {
                (StatusCode::FORBIDDEN, "cap_denied")
            }
            MnemeError::PromoteDenied => (StatusCode::FORBIDDEN, "promote_denied"),
            MnemeError::BelowTierPolicy { .. } => (StatusCode::FORBIDDEN, "below_tier"),
            MnemeError::IndexPathInvalid => (StatusCode::NOT_FOUND, "not_found"),
            MnemeError::Forgotten => (StatusCode::GONE, "forgotten"),
            MnemeError::RootSigInvalid
            | MnemeError::RootInconsistent
            | MnemeError::RootReplayed
            | MnemeError::ReceiptRootMismatch
            | MnemeError::ObjectTampered
            | MnemeError::UnauthorizedWriter => (StatusCode::FORBIDDEN, "verify_failed"),
            _ => (StatusCode::INTERNAL_SERVER_ERROR, "kernel_error"),
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

    const RATE_LIMIT_STALE_WINDOW_AGE: Duration = Duration::from_secs(61);
    const RATE_LIMIT_MULTI_REQUEST_TEST_LIMIT: u32 = 10;
    const RATE_LIMIT_SINGLE_REQUEST_TEST_LIMIT: u32 = 1;

    fn fill_active_rate_limit_windows(limiter: &mut RateLimiter, started_at: Instant) {
        for subject_index in 0..MAX_RATE_LIMIT_SUBJECT_WINDOWS {
            limiter
                .windows
                .insert(format!("subject-{subject_index}"), (1, started_at));
        }
    }

    fn expect_oversized_capability_error(token: &str, context: &str) -> ApiError {
        match parse_capability_b64(token) {
            Ok(_) => panic!("{context}: oversized capability unexpectedly parsed"),
            Err(err) => err,
        }
    }

    fn expect_rate_limit_allowed(limiter: &mut RateLimiter, subject: &str, context: &str) {
        limiter
            .check(subject)
            .unwrap_or_else(|err| panic!("{context}: rate limiter unexpectedly rejected: {err:?}"));
    }

    fn expect_rate_limit_denied(
        limiter: &mut RateLimiter,
        subject: &str,
        context: &str,
    ) -> MnemeError {
        match limiter.check(subject) {
            Ok(()) => panic!("{context}: rate limiter unexpectedly allowed"),
            Err(err) => err,
        }
    }

    #[test]
    fn oversized_capability_rejected_before_decode() {
        let token = "A".repeat(MAX_CAPABILITY_B64_LEN + 1);
        let err = expect_oversized_capability_error(&token, "oversized capability guard");

        assert_eq!(err.status, StatusCode::UNAUTHORIZED);
        assert_eq!(err.message, "capability token too large");
    }

    #[test]
    fn rate_limiter_prunes_stale_subject_windows_on_check() {
        let mut limiter = RateLimiter::new(RATE_LIMIT_MULTI_REQUEST_TEST_LIMIT);
        let stale_started = Instant::now() - RATE_LIMIT_STALE_WINDOW_AGE;
        limiter
            .windows
            .insert("stale-a".to_string(), (1, stale_started));
        limiter
            .windows
            .insert("stale-b".to_string(), (1, stale_started));

        expect_rate_limit_allowed(&mut limiter, "fresh", "fresh subject after stale pruning");

        assert_eq!(limiter.windows.len(), 1);
        assert!(limiter.windows.contains_key("fresh"));
    }

    #[test]
    fn rate_limiter_preserves_live_subject_window_while_pruning_stale_ones() {
        let mut limiter = RateLimiter::new(RATE_LIMIT_SINGLE_REQUEST_TEST_LIMIT);
        let stale_started = Instant::now() - RATE_LIMIT_STALE_WINDOW_AGE;
        expect_rate_limit_allowed(&mut limiter, "live", "first live subject request");
        limiter
            .windows
            .insert("stale".to_string(), (1, stale_started));

        let err = expect_rate_limit_denied(&mut limiter, "live", "live subject remains limited");

        assert!(matches!(err, MnemeError::CapDenied));
        assert_eq!(limiter.windows.len(), 1);
        assert!(limiter.windows.contains_key("live"));
    }

    #[test]
    fn rate_limiter_rejects_new_subject_when_active_window_cap_is_full() {
        let mut limiter = RateLimiter::new(RATE_LIMIT_MULTI_REQUEST_TEST_LIMIT);
        let now = Instant::now();
        fill_active_rate_limit_windows(&mut limiter, now);

        let err = expect_rate_limit_denied(
            &mut limiter,
            "overflow-subject",
            "active window cap overflow",
        );

        assert!(matches!(err, MnemeError::CapDenied));
        assert_eq!(limiter.windows.len(), MAX_RATE_LIMIT_SUBJECT_WINDOWS);
        assert!(!limiter.windows.contains_key("overflow-subject"));
    }

    #[test]
    fn rate_limiter_allows_existing_subject_when_active_window_cap_is_full() {
        let mut limiter = RateLimiter::new(RATE_LIMIT_MULTI_REQUEST_TEST_LIMIT);
        let now = Instant::now();
        fill_active_rate_limit_windows(&mut limiter, now);

        expect_rate_limit_allowed(
            &mut limiter,
            "subject-7",
            "existing subject within active window cap",
        );

        assert_eq!(limiter.windows.len(), MAX_RATE_LIMIT_SUBJECT_WINDOWS);
        assert_eq!(limiter.windows["subject-7"].0, 2);
    }
}

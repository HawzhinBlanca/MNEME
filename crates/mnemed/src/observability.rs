//! Tracing subscriber + optional OTLP export for L3 audit events (WO-20, blueprint §15.4).
//!
//! Audit emitters use the shared `mneme.audit` tracing target. When
//! `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set,
//! structured audit events are exported as OpenTelemetry span events in addition
//! to stdout logs. Without OTLP, operators can still scrape JSON logs or filter
//! `RUST_LOG=mneme.audit=info`.

use opentelemetry::global;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_sdk::trace::TracerProvider;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

pub use mneme_store::AUDIT_TARGET;

/// Default filter keeps general noise at `info` while always exporting audit events.
const DEFAULT_FILTER: &str = "info,mneme.audit=info";

/// Install the process-global tracing subscriber.
///
/// Honors `RUST_LOG` when set; otherwise uses [`DEFAULT_FILTER`]. When an OTLP
/// traces endpoint is configured via standard OpenTelemetry env vars, audit
/// events are bridged to the configured collector.
pub fn init_observability() -> Result<(), String> {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(DEFAULT_FILTER))
        .map_err(|err| format!("invalid tracing env filter: {err}"))?;

    if otlp_traces_endpoint_configured() {
        init_with_otlp(filter)
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .try_init()
            .map_err(|err| format!("tracing subscriber already initialized: {err}"))
    }
}

fn otlp_traces_endpoint_configured() -> bool {
    std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").is_ok()
        || std::env::var("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT").is_ok()
}

fn init_with_otlp(filter: EnvFilter) -> Result<(), String> {
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_tonic()
        .build()
        .map_err(|err| format!("OTLP span exporter build failed: {err}"))?;

    let provider = TracerProvider::builder()
        .with_simple_exporter(exporter)
        .build();

    let tracer = provider.tracer("mnemed");
    global::set_tracer_provider(provider);

    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .with(otel_layer)
        .try_init()
        .map_err(|err| format!("tracing subscriber already initialized: {err}"))
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_FILTER;
    use tracing_subscriber::EnvFilter;

    #[test]
    fn default_filter_exports_audit_target() {
        EnvFilter::try_new(DEFAULT_FILTER).expect("default audit filter should parse");
    }
}

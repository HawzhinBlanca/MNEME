//! `mneme-mcp` — stdio MCP server for verified agent memory (blueprint §14.1).

use mneme_mcp::{default_store_path, open_runtime, server::run_stdio_loop};
use tracing_subscriber::EnvFilter;

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("mneme_mcp=info".parse()?))
        .with_writer(std::io::stderr)
        .init();

    let store_path = default_store_path();
    let runtime = open_runtime(&store_path)?;
    tracing::info!(path = %runtime.store_path.display(), "mneme-mcp store ready");
    run_stdio_loop(&runtime.handlers)?;
    Ok(())
}

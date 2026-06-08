use clap::Parser;
use mnemed::ServerConfig;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "mnemed", about = "MNEME local-first daemon")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7845")]
    http: String,
    #[arg(long)]
    grpc: Option<String>,
    #[arg(long)]
    store: PathBuf,
    #[arg(long)]
    unix_socket: Option<PathBuf>,
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u32).range(1..))]
    rate_limit_per_minute: u32,
}

#[tokio::main]
async fn main() {
    if let Err(err) = mnemed::init_observability() {
        eprintln!("failed to initialize observability: {err}");
        std::process::exit(1);
    }
    let args = Args::parse();
    let config = match server_config_from_args(&args) {
        Ok(config) => config,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    };
    let server = match mnemed::start(config, &args.store).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to start mnemed: {e}");
            std::process::exit(1);
        }
    };
    println!("mnemed listening on http://{}", server.http_addr);
    if let Some(g) = server.grpc_addr {
        println!("mnemed gRPC on {g}");
    }
    if let Some(path) = &server.unix_socket {
        println!("mnemed Unix socket at {}", path.display());
    }
    if let Err(e) = wait_for_shutdown_signal(tokio::signal::ctrl_c()).await {
        eprintln!("{e}");
        server.shutdown().await;
        std::process::exit(1);
    }
    server.shutdown().await;
}

async fn wait_for_shutdown_signal(
    signal: impl std::future::Future<Output = std::io::Result<()>>,
) -> Result<(), String> {
    signal
        .await
        .map_err(|e| format!("failed to listen for shutdown signal: {e}"))
}

fn server_config_from_args(args: &Args) -> Result<ServerConfig, String> {
    let http_addr = args
        .http
        .parse()
        .map_err(|e| format!("invalid --http address: {e}"))?;
    if !http_addr.ip().is_loopback() {
        return Err(
            "refusing non-loopback --http bind without TLS (use 127.0.0.1 or enable a TLS front)"
                .into(),
        );
    }
    let grpc_addr = match args.grpc.as_deref() {
        Some(s) => Some(
            s.parse()
                .map_err(|e| format!("invalid --grpc address: {e}"))?,
        ),
        None => None,
    };
    Ok(ServerConfig {
        http_addr,
        grpc_addr,
        unix_socket: args.unix_socket.clone(),
        rate_limit_per_minute: args.rate_limit_per_minute,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expect_cli_args(args: &[&str], context: &str) -> Args {
        Args::try_parse_from(args.iter().copied())
            .unwrap_or_else(|err| panic!("{context}: CLI args parse failed: {err}"))
    }

    fn expect_server_config(args: &Args, context: &str) -> ServerConfig {
        server_config_from_args(args)
            .unwrap_or_else(|err| panic!("{context}: server config build failed: {err}"))
    }

    async fn expect_shutdown_signal_success(
        signal: impl std::future::Future<Output = Result<(), String>>,
        context: &str,
    ) {
        signal
            .await
            .unwrap_or_else(|err| panic!("{context}: shutdown signal unexpectedly failed: {err}"));
    }

    async fn expect_shutdown_signal_error(
        signal: impl std::future::Future<Output = Result<(), String>>,
        context: &str,
    ) -> String {
        match signal.await {
            Ok(()) => panic!("{context}: expected shutdown signal error"),
            Err(err) => err,
        }
    }

    #[test]
    fn cli_rate_limit_flag_feeds_server_config() {
        let args = expect_cli_args(
            &[
                "mnemed",
                "--store",
                "/tmp/mneme-store",
                "--rate-limit-per-minute",
                "7",
            ],
            "rate-limit CLI config",
        );
        let config = expect_server_config(&args, "rate-limit CLI config");

        assert_eq!(config.rate_limit_per_minute, 7);
    }

    #[test]
    fn cli_unix_socket_flag_feeds_server_config() {
        let args = expect_cli_args(
            &[
                "mnemed",
                "--store",
                "/tmp/mneme-store",
                "--unix-socket",
                "/tmp/mnemed.sock",
            ],
            "Unix socket CLI config",
        );
        let config = expect_server_config(&args, "Unix socket CLI config");

        assert_eq!(
            config.unix_socket.as_deref(),
            Some(std::path::Path::new("/tmp/mnemed.sock"))
        );
    }

    #[tokio::test]
    async fn shutdown_signal_success_is_ok() {
        expect_shutdown_signal_success(
            wait_for_shutdown_signal(async { Ok(()) }),
            "successful shutdown signal",
        )
        .await;
    }

    #[tokio::test]
    async fn shutdown_signal_error_is_reported() {
        let err = expect_shutdown_signal_error(
            wait_for_shutdown_signal(async {
                Err(std::io::Error::other("signal listener unavailable"))
            }),
            "failed shutdown signal",
        )
        .await;

        assert!(
            err.contains("failed to listen for shutdown signal"),
            "unexpected signal error: {err}"
        );
        assert!(
            err.contains("signal listener unavailable"),
            "underlying signal error was lost: {err}"
        );
    }
}

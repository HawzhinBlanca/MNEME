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
    tracing_subscriber::fmt::init();
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

    #[test]
    fn cli_rate_limit_flag_feeds_server_config() {
        let args = Args::try_parse_from([
            "mnemed",
            "--store",
            "/tmp/mneme-store",
            "--rate-limit-per-minute",
            "7",
        ])
        .expect("parse args");
        let config = server_config_from_args(&args).expect("server config");

        assert_eq!(config.rate_limit_per_minute, 7);
    }

    #[test]
    fn cli_unix_socket_flag_feeds_server_config() {
        let args = Args::try_parse_from([
            "mnemed",
            "--store",
            "/tmp/mneme-store",
            "--unix-socket",
            "/tmp/mnemed.sock",
        ])
        .expect("parse args");
        let config = server_config_from_args(&args).expect("server config");

        assert_eq!(
            config.unix_socket.as_deref(),
            Some(std::path::Path::new("/tmp/mnemed.sock"))
        );
    }

    #[tokio::test]
    async fn shutdown_signal_success_is_ok() {
        wait_for_shutdown_signal(async { Ok(()) })
            .await
            .expect("successful shutdown signal");
    }

    #[tokio::test]
    async fn shutdown_signal_error_is_reported() {
        let err = wait_for_shutdown_signal(async {
            Err(std::io::Error::other("signal listener unavailable"))
        })
        .await
        .expect_err("signal listener errors must be surfaced");

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

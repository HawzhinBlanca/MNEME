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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let http_addr = match args.http.parse() {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("invalid --http address: {e}");
            std::process::exit(1);
        }
    };
    let grpc_addr = match args.grpc {
        Some(s) => match s.parse() {
            Ok(addr) => Some(addr),
            Err(e) => {
                eprintln!("invalid --grpc address: {e}");
                std::process::exit(1);
            }
        },
        None => None,
    };
    let config = ServerConfig {
        http_addr,
        grpc_addr,
        rate_limit_per_minute: 120,
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
    let _ = tokio::signal::ctrl_c().await;
    server.shutdown().await;
}

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
    let http_addr: std::net::SocketAddr = args.http.parse().expect("http addr");
    let grpc_addr = args.grpc.map(|s| s.parse().expect("grpc addr"));
    let config = ServerConfig {
        http_addr,
        grpc_addr,
        rate_limit_per_minute: 120,
    };
    let server = mnemed::start(config, &args.store).await;
    println!("mnemed listening on http://{}", server.http_addr);
    if let Some(g) = server.grpc_addr {
        println!("mnemed gRPC on {g}");
    }
    tokio::signal::ctrl_c().await.expect("ctrl-c");
    server.shutdown().await;
}

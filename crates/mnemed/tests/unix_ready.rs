use std::path::Path;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;

const UNIX_SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(1);
const UNIX_SOCKET_READY_RETRY: Duration = Duration::from_millis(10);

fn unix_socket_ready_deadline() -> Instant {
    Instant::now() + UNIX_SOCKET_READY_TIMEOUT
}

async fn wait_for_unix_socket_ready_retry() {
    tokio::time::sleep(UNIX_SOCKET_READY_RETRY).await;
}

fn unix_socket_ready_timeout_message(path: &Path, err: &std::io::Error) -> String {
    format!(
        "Unix socket did not accept connections before timeout: {} ({err})",
        path.display()
    )
}

fn panic_unix_socket_not_accepting(path: &Path, err: &std::io::Error) -> ! {
    panic!("{}", unix_socket_ready_timeout_message(path, err));
}

pub async fn wait_for_unix_socket_accepting(path: &Path) {
    let deadline = unix_socket_ready_deadline();

    loop {
        match UnixStream::connect(path).await {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    panic_unix_socket_not_accepting(path, &e);
                }
            }
        }

        wait_for_unix_socket_ready_retry().await;
    }
}

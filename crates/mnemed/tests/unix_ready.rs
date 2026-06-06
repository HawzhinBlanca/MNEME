use std::path::Path;
use std::time::{Duration, Instant};
use tokio::net::UnixStream;

const UNIX_SOCKET_READY_TIMEOUT: Duration = Duration::from_secs(1);
const UNIX_SOCKET_READY_RETRY: Duration = Duration::from_millis(10);

pub async fn wait_for_unix_socket_accepting(path: &Path) {
    let deadline = Instant::now() + UNIX_SOCKET_READY_TIMEOUT;

    loop {
        match UnixStream::connect(path).await {
            Ok(stream) => {
                drop(stream);
                return;
            }
            Err(e) => {
                if Instant::now() >= deadline {
                    panic!(
                        "Unix socket did not accept connections before timeout: {} ({e})",
                        path.display()
                    );
                }
            }
        }

        tokio::time::sleep(UNIX_SOCKET_READY_RETRY).await;
    }
}

use env_logger;
use tokio::net::TcpListener;

const ADDRESS: &str = "127.0.0.1:1080";

#[tokio::main]
async fn main() {
    env_logger::init();

    let listener = TcpListener::bind(ADDRESS).await.unwrap();

    loop {
        let (socket, _) = listener.accept().await.unwrap();
        // A new task is spawned for each inbound socket. The socket is
        // moved to the new task and processed there.
        tokio::spawn(async move {
            socks5::process(socket).await;
        });
    }
}

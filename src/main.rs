use env_logger;

const ADDRESS: &str = "127.0.0.1";
const PORT: u16 = 1080;

use socks5::server::SOCKS5Server;

#[tokio::main]
async fn main() {
    env_logger::init();

    SOCKS5Server::new(ADDRESS.to_string(), PORT).run().await;
}

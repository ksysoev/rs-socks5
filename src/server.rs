use tokio::net::TcpListener;

mod connection;

pub struct SOCKS5Server {
    address: String,
    port: u16,
}

impl SOCKS5Server {
    pub fn new(address: String, port: u16) -> Self {
        SOCKS5Server { address, port }
    }

    pub async fn run(&self) {
        let address = format!("{}:{}", self.address, self.port);
        let listener = TcpListener::bind(address).await.unwrap();

        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let mut connection = connection::SOCKS5ClientConnection::new(socket);
            tokio::spawn(async move {
                connection.process().await;
            });
        }
    }
}

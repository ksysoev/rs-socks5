use env_logger;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::ToSocketAddrs;

use log::{debug, trace};
use std::io;
use tokio::net::{TcpListener, TcpStream};

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
            process(socket).await;
        });
    }
}

async fn process(stream: TcpStream) {
    let mut buf = [0u8; 2];
    read_exact(&stream, &mut buf).await.unwrap();

    if buf[0] != 0x05 {
        trace!("Invalid SOCKS5 version");
        return;
    }

    let num_methods = buf[1] as usize;

    let mut methods = vec![0; num_methods];
    for _ in 0..num_methods {
        let mut buf = [0u8; 1];
        read_exact(&stream, &mut buf).await.unwrap();
        methods.push(buf[0]);
    }

    if !methods.contains(&0x00) {
        trace!("No supported authentication methods");
        return;
    }

    // send the SOCKS5 handshake response
    write_all(&stream, &[0x05, 0x00]).await.unwrap();

    // read the SOCKS5 request
    let mut buf = [0; 4];
    read_exact(&stream, &mut buf).await.unwrap();

    // check the SOCKS5 version and command
    if buf[0] != 0x05 {
        trace!("Invalid SOCKS5 version");
        return;
    }

    if buf[1] != 0x01 {
        trace!("Unsupported SOCKS5 command");
        return;
    }

    // handle the SOCKS5 request
    let addr = match buf[3] {
        0x01 => {
            let mut buf = [0; 4];
            read_exact(&stream, &mut buf).await.unwrap();
            IpAddr::V4(Ipv4Addr::from(buf))
        }
        0x04 => {
            let mut buf = [0; 16];
            read_exact(&stream, &mut buf).await.unwrap();
            IpAddr::V6(Ipv6Addr::from(buf))
        }
        0x03 => {
            let mut buf = [0; 1];
            read_exact(&stream, &mut buf).await.unwrap();
            let len = buf[0] as usize;
            let mut buf = vec![0; len];
            read_exact(&stream, &mut buf).await.unwrap();
            let domain = String::from_utf8_lossy(&buf);
            let mut addrs = (domain.as_ref(), 0).to_socket_addrs().unwrap();
            addrs.next().unwrap().ip()
        }
        _ => {
            trace!("Invalid SOCKS5 address type");
            return;
        }
    };

    let mut buf = [0; 2];
    read_exact(&stream, &mut buf).await.unwrap();
    let port = u16::from_be_bytes(buf);

    debug!("SOCKS5 request: {}:{} ({:?})", addr, port, buf);

    let dest_stream = match TcpStream::connect((addr, port)).await {
        Ok(stream) => stream,
        Err(e) => {
            debug!("Failed to connect to destination: {}", e);

            write_all(&stream, &[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            return;
        }
    };

    write_all(&stream, &[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();

    loop {
        tokio::select! {
            _ = stream.readable() => {
                let mut buf = [0; 4096];

                match stream.try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        write_all(&dest_stream, &buf[0..n]).await.unwrap();
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
            _ = dest_stream.readable() => {
                let mut buf = [0; 4096];

                match dest_stream.try_read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        write_all(&stream, &buf[0..n]).await.unwrap();
                    }
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(_) => {
                        break;
                    }
                }
            }
        }
    }
    debug!("Connection closed");
}

async fn read_exact(stream: &TcpStream, buf: &mut [u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        stream.readable().await?;

        match stream.try_read(&mut buf[offset..]) {
            Ok(0) => break,
            Ok(n) => {
                offset += n;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    Ok(())
}

async fn write_all(stream: &TcpStream, buf: &[u8]) -> std::io::Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        stream.writable().await?;

        match stream.try_write(&buf[offset..]) {
            Ok(0) => break,
            Ok(n) => {
                offset += n;
            }
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                continue;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }
    Ok(())
}

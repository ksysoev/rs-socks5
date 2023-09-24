use log::{debug, trace};
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::ToSocketAddrs;
use tokio::net::TcpStream;

const PROTOCOL_VERSION: u8 = 0x05;

const NO_AUTHENTICATION_REQUIRED: u8 = 0x00;

const PROXY_CMD_CONNECT: u8 = 0x01;
// const PROXY_CMD_BIND: u8 = 0x02;
// const PROXY_CMD_UDP_ASSOCIATE: u8 = 0x03;

const ADDRESS_TYPE_IPV4: u8 = 0x01;
const ADDRESS_TYPE_DOMAIN_NAME: u8 = 0x03;
const ADDRESS_TYPE_IPV6: u8 = 0x04;

const REPLY_SUCCEEDED: u8 = 0x00;
// const REPLY_GENERAL_FAILURE: u8 = 0x01;
// const REPLY_CONNECTION_NOT_ALLOWED: u8 = 0x02;
// const REPLY_NETWORK_UNREACHABLE: u8 = 0x03;
// const REPLY_HOST_UNREACHABLE: u8 = 0x04;
const REPLY_CONNECTION_REFUSED: u8 = 0x05;
// const REPLY_TTL_EXPIRED: u8 = 0x06;
// const REPLY_COMMAND_NOT_SUPPORTED: u8 = 0x07;
// const REPLY_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
// const REPLY_UNASSIGNED: u8 = 0x09;

const RESERVED: u8 = 0x00;

const BUFFER_SIZE: usize = 4096;

pub async fn process(stream: TcpStream) {
    let mut buf = [0u8; 2];
    read_exact(&stream, &mut buf).await.unwrap();

    if buf[0] != PROTOCOL_VERSION {
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
    write_all(&stream, &[PROTOCOL_VERSION, NO_AUTHENTICATION_REQUIRED])
        .await
        .unwrap();

    // read the SOCKS5 request
    let mut buf = [0; 4];
    read_exact(&stream, &mut buf).await.unwrap();

    // check the SOCKS5 version and command
    if buf[0] != PROTOCOL_VERSION {
        trace!("Invalid SOCKS5 version");
        return;
    }

    if buf[1] != PROXY_CMD_CONNECT {
        trace!("Unsupported SOCKS5 command");
        return;
    }

    let mut address_info: Vec<u8> = Vec::new();
    address_info.push(buf[3]);
    // handle the SOCKS5 request
    let addr = match buf[3] {
        ADDRESS_TYPE_IPV4 => {
            let mut buf = [0; 4];
            read_exact(&stream, &mut buf).await.unwrap();
            address_info.extend_from_slice(&buf);
            IpAddr::V4(Ipv4Addr::from(buf))
        }
        ADDRESS_TYPE_IPV6 => {
            let mut buf = [0; 16];
            read_exact(&stream, &mut buf).await.unwrap();
            address_info.extend_from_slice(&buf);
            IpAddr::V6(Ipv6Addr::from(buf))
        }
        ADDRESS_TYPE_DOMAIN_NAME => {
            let mut buf = [0; 1];
            read_exact(&stream, &mut buf).await.unwrap();
            address_info.extend_from_slice(&buf);
            let len = buf[0] as usize;
            let mut buf = vec![0; len];
            read_exact(&stream, &mut buf).await.unwrap();
            address_info.extend_from_slice(&buf);
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
    address_info.extend_from_slice(&buf);
    let port = u16::from_be_bytes(buf);

    debug!("SOCKS5 request: {}:{} ({:?})", addr, port, buf);

    let dest_stream = match TcpStream::connect((addr, port)).await {
        Ok(stream) => stream,
        Err(e) => {
            debug!("Failed to connect to destination: {}", e);
            let mut data = vec![PROTOCOL_VERSION, REPLY_CONNECTION_REFUSED, RESERVED];
            data.append(&mut address_info);
            write_all(&stream, &data).await.unwrap();
            return;
        }
    };

    let mut data = vec![PROTOCOL_VERSION, REPLY_SUCCEEDED, RESERVED];
    data.append(&mut address_info);
    write_all(&stream, &mut data).await.unwrap();

    loop {
        tokio::select! {
            _ = stream.readable() => {
                let mut buf = [0; BUFFER_SIZE];

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
                let mut buf = [0; BUFFER_SIZE];

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

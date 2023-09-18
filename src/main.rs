use std::io::{Read, Write};
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::ToSocketAddrs;
use std::net::{TcpListener, TcpStream};

const ADDRESS: &str = "127.0.0.1:1080";

fn handle_client(mut stream: TcpStream) {
    println!("New client: {}", stream.peer_addr().unwrap());

    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).unwrap();

    if buf[0] != 0x05 {
        println!("Invalid SOCKS5 version");
        return;
    }

    let num_methods = buf[1] as usize;
    println!("SOCKS5 number methods: ({:?})", num_methods);

    let mut methods = vec![0; num_methods];
    for _ in 0..num_methods {
        let mut buf = [0u8; 1];
        println!("SOCKS5 reading method");
        stream.read_exact(&mut buf).unwrap();
        println!("SOCKS5 method: ({:?})", buf);
        methods.push(buf[0]);
    }

    println!("SOCKS5 methods: ({:?})", methods);
    if !methods.contains(&0x00) {
        println!("No supported authentication methods");
        return;
    }

    // send the SOCKS5 handshake response
    stream.write(&[0x05, 0x00]).unwrap();
    stream.flush().unwrap();

    // read the SOCKS5 request
    let mut buf = [0; 4];
    stream.read_exact(&mut buf).unwrap();

    println!("SOCKS5 request: ({:?})", buf);

    // check the SOCKS5 version and command
    if buf[0] != 0x05 {
        println!("Invalid SOCKS5 version");
        return;
    }

    if buf[1] != 0x01 {
        println!("Unsupported SOCKS5 command");
        return;
    }

    // handle the SOCKS5 request
    let addr = match buf[3] {
        0x01 => {
            let mut buf = [0; 4];
            stream.read_exact(&mut buf).unwrap();
            IpAddr::V4(Ipv4Addr::from(buf))
        }
        0x04 => {
            let mut buf = [0; 16];
            stream.read_exact(&mut buf).unwrap();
            IpAddr::V6(Ipv6Addr::from(buf))
        }
        0x03 => {
            let mut buf = [0; 1];
            stream.read_exact(&mut buf).unwrap();
            let len = buf[0] as usize;
            let mut buf = vec![0; len];
            stream.read_exact(&mut buf).unwrap();
            let domain = String::from_utf8_lossy(&buf);
            let mut addrs = (domain.as_ref(), 0).to_socket_addrs().unwrap();
            addrs.next().unwrap().ip()
        }
        _ => {
            println!("Invalid SOCKS5 address type");
            return;
        }
    };

    let mut buf = [0; 2];
    stream.read_exact(&mut buf).unwrap();
    let port = u16::from_be_bytes(buf);

    println!("SOCKS5 request: {}:{} ({:?})", addr, port, buf);

    let mut dest_stream = match TcpStream::connect((addr, port)) {
        Ok(stream) => stream,
        Err(e) => {
            println!("Failed to connect to destination: {}", e);
            stream
                .write(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .unwrap();
            stream.flush().unwrap();
            return;
        }
    };

    // send the SOCKS5 request response
    stream
        .write(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .unwrap();
    stream.flush().unwrap();

    loop {
        let mut client_buf = [0; 4096];
        match stream.read(&mut client_buf) {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                dest_stream.write_all(&client_buf[0..n]).unwrap();
                dest_stream.flush().unwrap();
            }
            Err(e) => {
                println!("Failed to read from client: {}", e);
                break;
            }
        }

        let mut dest_buf = [0; 4096];

        match dest_stream.read(&mut dest_buf) {
            Ok(n) => {
                if n == 0 {
                    break;
                }
                stream.write_all(&dest_buf[0..n]).unwrap();
                stream.flush().unwrap();
            }
            Err(e) => {
                println!("Failed to read from destination: {}", e);
                break;
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(ADDRESS)?;

    // accept connections and process them serially
    for stream in listener.incoming() {
        handle_client(stream?);
    }
    Ok(())
}

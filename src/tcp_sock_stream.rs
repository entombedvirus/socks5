use std::{
    io,
    net::{SocketAddr, TcpStream},
};

use crate::proto::{self, ServerStatus};

pub struct ConnectRequest {
    pub server_addr: String,
    pub dest_addr: String,
    pub dest_port: u16,
    pub supported_auth_methods: Vec<proto::AuthMethod>,
}

pub fn connect(req: ConnectRequest) -> io::Result<TcpStream> {
    let mut conn = TcpStream::connect(&req.server_addr)?;
    socks_handshake(&mut conn, &req)?;
    Ok(conn)
}

fn socks_handshake(conn: &mut TcpStream, req: &ConnectRequest) -> io::Result<()> {
    let resp: Box<proto::ServerAuthChoice> =
        proto::send_recv(conn, proto::ClientGreeting(vec![proto::AuthMethod::NoAuth]))?;
    println!("got resp: {resp:?}");
    match *resp {
        proto::ServerAuthChoice(proto::AuthMethod::NoAuth) => {
            let dest_addr = match req.dest_addr.parse::<SocketAddr>() {
                Ok(SocketAddr::V4(v4)) => proto::Address::Ipv4(*v4.ip()),
                Ok(SocketAddr::V6(v6)) => proto::Address::Ipv6(*v6.ip()),
                // must be a domain name
                Err(_) => proto::Address::DomainName(req.dest_addr.to_owned()),
            };
            let resp: Box<proto::ServerResponse> = proto::send_recv(
                conn,
                proto::ClientConnectionRequest {
                    cmd: proto::ClientCommand::EstablishConnection,
                    dest_port: req.dest_port,
                    dest_addr,
                },
            )?;
            println!("got resp: {resp:?}");
            match *resp {
                proto::ServerResponse(proto::ServerStatus::RequestGranted) => Ok(()),
                _ => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("proxy rejected establish connection with: {resp:?}"),
                )),
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "auth method negotiation failed",
        )),
    }
}

use std::{io, net::TcpStream};

use crate::proto;

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
            let resp: Box<proto::ServerResponse> = proto::send_recv(
                conn,
                proto::ClientConnectionRequest {
                    cmd: proto::ClientCommand::EstablishConnection,
                    dest_port: req.dest_port,
                    dest_addr: req.dest_addr.parse()?,
                },
            )?;
            println!("got resp: {resp:?}");
            let status = resp.status;
            if status == proto::ServerStatus::RequestGranted {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("proxy rejected establish connection with status: {status:?}"),
                ))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "auth method negotiation failed",
        )),
    }
}

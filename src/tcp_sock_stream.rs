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
    let resp: proto::ServerAuthChoice = dbg!(proto::send_recv(
        conn,
        proto::ClientGreeting(vec![proto::AuthMethod::NoAuth])
    )?);

    if resp.0 != proto::AuthMethod::NoAuth {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "auth method negotiation failed. expected: {:?}, got: {:?}",
                proto::AuthMethod::NoAuth,
                resp.0
            ),
        ));
    }

    let resp: proto::ServerResponse = dbg!(proto::send_recv(
        conn,
        proto::ClientConnectionRequest {
            cmd: proto::ClientCommand::EstablishConnection,
            dest_port: req.dest_port,
            dest_addr: req.dest_addr.parse()?,
        },
    )?);

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

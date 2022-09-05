use std::{io, net::TcpStream};

use crate::proto;

pub struct ConnectRequest {
    pub server_addr: String,
    pub dest_addr: String,
    pub supported_auth_methods: Vec<proto::AuthMethod>,
}

pub fn connect(req: ConnectRequest) -> io::Result<TcpStream> {
    let mut conn = TcpStream::connect(&req.server_addr)?;
    socks_handshake(&mut conn, &req)?;
    Ok(conn)
}

fn socks_handshake(conn: &mut TcpStream, _req: &ConnectRequest) -> io::Result<()> {
    let resp = proto::write_message(
        conn,
        proto::ClientGreeting(vec![proto::AuthMethod::NoAuth, proto::AuthMethod::UserPass]),
    )?;
    println!("got resp: {resp:?}");
    todo!()
}

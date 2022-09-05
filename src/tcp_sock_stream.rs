use std::{
    io::{self, ErrorKind, Read, Write},
    net::TcpStream,
};

pub struct ConnectRequest {
    pub server_addr: String,
    pub dest_addr: String,
}

pub fn connect(req: ConnectRequest) -> io::Result<TcpStream> {
    let mut conn = TcpStream::connect(&req.server_addr)?;
    socks_handshake(&mut conn, &req)?;
    Ok(conn)
}

fn socks_handshake(conn: &mut TcpStream, _req: &ConnectRequest) -> io::Result<()> {
    let resp = write_protocol_message(conn, ClientGreeting(vec![AuthMethod::NoAuth]))?;
    println!("got resp: {resp:?}");
    todo!()
}

fn write_protocol_message(
    conn: &mut TcpStream,
    msg_to_send: ClientGreeting,
) -> io::Result<ServerAuthChoice> {
    msg_to_send.write_to(conn)?;
    ServerAuthChoice::read_from(conn)
}

#[derive(Debug)]
enum AuthMethod {
    NoAuth,
}

impl TryFrom<u8> for AuthMethod {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::NoAuth),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unxpected AuthMethod: {value}"),
            )),
        }
    }
}

impl Into<u8> for &AuthMethod {
    fn into(self) -> u8 {
        match *self {
            AuthMethod::NoAuth => 0x00,
        }
    }
}

const SOCKS_VERSION: u8 = 0x05;
#[derive(Debug)]
struct ClientGreeting(Vec<AuthMethod>);

impl ClientGreeting {
    fn write_to(&self, conn: &mut TcpStream) -> io::Result<()> {
        let mut buf = Vec::with_capacity(1 + 1 + self.0.len());
        buf.push(SOCKS_VERSION);
        buf.push(self.0.len() as u8);
        for auth_method in &self.0 {
            buf.push(auth_method.into());
        }
        conn.write_all(&buf)?;
        Ok(())
    }
}

#[derive(Debug)]
struct ServerAuthChoice(AuthMethod);
impl ServerAuthChoice {
    fn read_from(conn: &mut TcpStream) -> io::Result<Self> {
        let mut buf = [0_u8; 2];
        conn.read_exact(&mut buf)?;
        if buf[0] != SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected socks version: {}, got: {}", SOCKS_VERSION, buf[0]),
            ));
        }

        Ok(Self(AuthMethod::try_from(buf[1])?))
    }
}

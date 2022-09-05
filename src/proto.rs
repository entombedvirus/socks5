use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

const SOCKS_VERSION: u8 = 0x05;

pub fn write_message(
    conn: &mut TcpStream,
    msg_to_send: ClientGreeting,
) -> io::Result<ServerAuthChoice> {
    msg_to_send.write_to(conn)?;
    ServerAuthChoice::read_from(conn)
}

#[derive(Debug)]
pub enum AuthMethod {
    NoAuth,
    GssApi,
    UserPass,
}

impl TryFrom<u8> for AuthMethod {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::NoAuth),
            0x01 => Ok(Self::GssApi),
            0x02 => Ok(Self::UserPass),
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
            AuthMethod::GssApi => 0x01,
            AuthMethod::UserPass => 0x02,
        }
    }
}

#[derive(Debug)]
pub struct ClientGreeting(pub Vec<AuthMethod>);

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
pub struct ServerAuthChoice(pub AuthMethod);
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

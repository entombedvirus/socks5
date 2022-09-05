use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, TcpStream},
};

const SOCKS_VERSION: u8 = 0x05;

pub trait Sendable {
    fn write_to(&self, conn: &mut TcpStream) -> io::Result<()>;
}

pub trait Recievable {
    fn read_from(conn: &mut TcpStream) -> io::Result<Box<Self>>;
}

pub fn send_recv<Req: Sendable, Resp: Recievable>(
    conn: &mut TcpStream,
    msg_to_send: Req,
) -> io::Result<Box<Resp>> {
    msg_to_send.write_to(conn)?;
    Resp::read_from(conn)
}

#[derive(Debug, Clone, Copy)]
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
        match self {
            AuthMethod::NoAuth => 0x00,
            AuthMethod::GssApi => 0x01,
            AuthMethod::UserPass => 0x02,
        }
    }
}

#[derive(Debug)]
pub struct ClientGreeting(pub Vec<AuthMethod>);

impl Sendable for ClientGreeting {
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
impl Recievable for ServerAuthChoice {
    fn read_from(conn: &mut TcpStream) -> io::Result<Box<Self>> {
        let mut buf = [0_u8; 2];
        conn.read_exact(&mut buf)?;
        if buf[0] != SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected socks version: {}, got: {}", SOCKS_VERSION, buf[0]),
            ));
        }

        Ok(Box::new(Self(AuthMethod::try_from(buf[1])?)))
    }
}

#[derive(Debug)]
pub enum Address {
    Ipv4(Ipv4Addr),
    DomainName(String),
    Ipv6(Ipv6Addr),
}

impl Into<Vec<u8>> for &Address {
    fn into(self) -> Vec<u8> {
        let mut buf = vec![];
        match self {
            Address::Ipv4(addr) => {
                buf.push(0x01);
                buf.extend_from_slice(&addr.octets());
            }
            Address::DomainName(dn) => {
                buf.push(0x03);
                buf.push(dn.len() as u8);
                buf.extend_from_slice(dn.as_bytes());
            }
            Address::Ipv6(addr) => {
                buf.push(0x04);
                buf.extend_from_slice(&addr.octets());
            }
        }
        buf
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ClientCommand {
    EstablishConnection,
    EstablishPortBinding,
    AssociateUdpPort,
}

impl Into<u8> for ClientCommand {
    fn into(self) -> u8 {
        match self {
            Self::EstablishConnection => 0x01,
            Self::EstablishPortBinding => 0x02,
            Self::AssociateUdpPort => 0x03,
        }
    }
}

#[derive(Debug)]
pub struct ClientConnectionRequest {
    pub cmd: ClientCommand,
    pub dest_addr: Address,
    pub dest_port: u16,
}

impl Sendable for ClientConnectionRequest {
    fn write_to(&self, conn: &mut TcpStream) -> io::Result<()> {
        let mut buf = vec![];
        buf.push(SOCKS_VERSION);
        buf.push(self.cmd.into());
        buf.push(0x00); // RSV: must be always zero
        let addr_bytes: Vec<u8> = (&self.dest_addr).into();
        buf.extend_from_slice(&addr_bytes);
        buf.extend_from_slice(&self.dest_port.to_be_bytes());
        conn.write_all(&buf)
    }
}

#[derive(Debug)]
pub enum ServerStatus {
    RequestGranted,
    GeneralFailure,
    ConnectionNotAllowedByRuleset,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefusedByDestinationHost,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
}

impl TryFrom<u8> for ServerStatus {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x00 => Ok(Self::RequestGranted),
            0x01 => Ok(Self::GeneralFailure),
            0x02 => Ok(Self::ConnectionNotAllowedByRuleset),
            0x03 => Ok(Self::NetworkUnreachable),
            0x04 => Ok(Self::HostUnreachable),
            0x05 => Ok(Self::ConnectionRefusedByDestinationHost),
            0x06 => Ok(Self::TtlExpired),
            0x07 => Ok(Self::CommandNotSupported),
            0x08 => Ok(Self::AddressTypeNotSupported),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unxpected ServerStatus: {value}"),
            )),
        }
    }
}

#[derive(Debug)]
pub struct ServerResponse(pub ServerStatus);

impl Recievable for ServerResponse {
    fn read_from(conn: &mut TcpStream) -> io::Result<Box<Self>> {
        let mut buf = [0_u8; 2];
        conn.read_exact(&mut buf)?;
        if buf[0] != SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected socks version: {}, got: {}", SOCKS_VERSION, buf[0]),
            ));
        }
        Ok(Box::new(Self(ServerStatus::try_from(buf[1])?)))
    }
}
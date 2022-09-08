use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, TcpStream},
    str::FromStr,
};

use futures::Future;
use tokio::net::ToSocketAddrs;

pub const SOCKS_VERSION: u8 = 0x05;
pub const RESERVED: u8 = 0x00;

pub const EMPTY_ADDRESS: Address = Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0));

pub trait Sendable {
    fn write_to(&self, conn: &mut TcpStream) -> io::Result<()>;
}

pub trait Recievable {
    fn read_from(conn: &mut TcpStream) -> io::Result<Self>
    where
        Self: Sized;
}

pub fn send_recv<Req: Sendable, Resp: Recievable>(
    conn: &mut TcpStream,
    msg_to_send: Req,
) -> io::Result<Resp> {
    msg_to_send.write_to(conn)?;
    Resp::read_from(conn)
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AuthMethod {
    NoAuth = 0x00,
    GssApi = 0x01,
    UserPass = 0x02,
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

#[derive(Debug)]
pub enum Address {
    Ipv4(Ipv4Addr),
    DomainName(String),
    Ipv6(Ipv6Addr),
}

impl Address {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
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
impl FromStr for Address {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<std::net::SocketAddr>() {
            Ok(std::net::SocketAddr::V4(v4)) => Ok(Address::Ipv4(*v4.ip())),
            Ok(std::net::SocketAddr::V6(v6)) => Ok(Address::Ipv6(*v6.ip())),
            // must be a domain name
            Err(_) => Ok(Address::DomainName(s.to_owned())),
        }
    }
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

impl Address {
    pub fn to_ip_addr(&self) -> String {
        match self {
            Address::Ipv4(addr) => addr.to_string(),
            Address::DomainName(dn) => dn.to_owned(),
            Address::Ipv6(addr) => addr.to_string(),
        }
    }
}

impl Recievable for Address {
    fn read_from(conn: &mut TcpStream) -> io::Result<Self> {
        let mut buf = [0_u8; 255];
        conn.read_exact(&mut buf[..1])?;
        match buf[0] {
            0x01 => {
                conn.read_exact(&mut buf[..4])?;
                let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                Ok(Self::Ipv4(addr))
            }
            0x03 => {
                conn.read_exact(&mut buf[..1])?;
                let dn_len = buf[0] as usize;
                conn.read_exact(&mut buf[..dn_len])?;
                let dn = String::from_utf8(buf[..dn_len].to_vec())
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
                Ok(Self::DomainName(dn))
            }
            0x04 => {
                let mut buf = [0_u8; 16];
                conn.read_exact(&mut buf)?;
                let addr = Ipv6Addr::from(buf);
                Ok(Self::Ipv6(addr))
            }
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("proto: failed to parse address. expected 0x01, 0x03, 0x04: got: {other}"),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ClientCommand {
    EstablishConnection = 0x01,
    EstablishPortBinding = 0x02,
    AssociateUdpPort = 0x03,
}

impl TryFrom<u8> for ClientCommand {
    type Error = io::Error;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::EstablishConnection),
            0x02 => Ok(Self::EstablishPortBinding),
            0x03 => Ok(Self::AssociateUdpPort),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "error parsing client command: got: {}, expected one of: {}, {}, {}",
                    value,
                    Self::EstablishConnection as u8,
                    Self::EstablishPortBinding as u8,
                    Self::AssociateUdpPort as u8,
                ),
            )),
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
        buf.push(self.cmd as u8);
        buf.push(0x00); // RSV: must be always zero
        let addr_bytes: Vec<u8> = (&self.dest_addr).into();
        buf.extend_from_slice(&addr_bytes);
        buf.extend_from_slice(&self.dest_port.to_be_bytes());
        conn.write_all(&buf)
    }
}

#[derive(Debug, PartialEq)]
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

impl Into<u8> for ServerStatus {
    fn into(self) -> u8 {
        match self {
            Self::RequestGranted => 0x00,
            Self::GeneralFailure => 0x01,
            Self::ConnectionNotAllowedByRuleset => 0x02,
            Self::NetworkUnreachable => 0x03,
            Self::HostUnreachable => 0x04,
            Self::ConnectionRefusedByDestinationHost => 0x05,
            Self::TtlExpired => 0x06,
            Self::CommandNotSupported => 0x07,
            Self::AddressTypeNotSupported => 0x08,
        }
    }
}

#[derive(Debug)]
pub struct ServerResponse {
    pub status: ServerStatus,
    pub bound_address: Address,
    pub bound_port: u16,
}

impl ServerResponse {
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(SOCKS_VERSION);
        buf.push(self.status as u8);
        buf.push(RESERVED);
        buf.extend_from_slice(&self.bound_address.as_bytes());
        buf.extend_from_slice(&self.bound_port.to_be_bytes());

        buf
    }
}

impl Recievable for ServerResponse {
    fn read_from(conn: &mut TcpStream) -> io::Result<Self> {
        let mut buf = [0_u8; 3];
        conn.read_exact(&mut buf)?;
        if buf[0] != SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected socks version: {}, got: {}", SOCKS_VERSION, buf[0]),
            ));
        }
        let status = ServerStatus::try_from(buf[1])?;
        if buf[2] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected RSV byte to be zero, got: {}", buf[2]),
            ));
        }

        let bound_address = Address::read_from(conn)?;

        let mut buf = [0u8; 2];
        conn.read_exact(&mut buf)?;
        let bound_port = u16::from_be_bytes(buf);

        Ok(Self {
            status,
            bound_address,
            bound_port,
        })
    }
}

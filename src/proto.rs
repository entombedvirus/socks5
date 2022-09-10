use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

pub const SOCKS_VERSION: u8 = 0x05;
pub const RESERVED: u8 = 0x00;
pub const EMPTY_ADDRESS: Address = Address::Ipv4(Ipv4Addr::new(0, 0, 0, 0));

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

#[derive(Debug)]
pub struct ClientGreeting(pub Vec<AuthMethod>);

#[derive(Debug)]
pub struct ServerAuthChoice(pub AuthMethod);

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

impl From<SocketAddr> for Address {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => Self::Ipv4(*addr.ip()),
            SocketAddr::V6(addr) => Self::Ipv6(*addr.ip()),
        }
    }
}

impl Address {
    pub fn to_string(&self) -> String {
        match self {
            Address::Ipv4(addr) => addr.to_string(),
            Address::DomainName(dn) => dn.to_owned(),
            Address::Ipv6(addr) => addr.to_string(),
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

#[derive(Debug, PartialEq)]
pub enum ServerStatus {
    RequestGranted = 0x00,
    GeneralFailure = 0x01,
    ConnectionNotAllowedByRuleset = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefusedByDestinationHost = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddressTypeNotSupported = 0x08,
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

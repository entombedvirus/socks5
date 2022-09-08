use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, TcpStream},
};

use crate::proto::*;

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

impl Sendable for ClientGreeting {
    fn write_to(&self, conn: &mut TcpStream) -> io::Result<()> {
        let mut buf = Vec::with_capacity(1 + 1 + self.0.len());
        buf.push(SOCKS_VERSION);
        buf.push(self.0.len() as u8);
        for &auth_method in &self.0 {
            buf.push(auth_method as u8);
        }
        conn.write_all(&buf)?;
        Ok(())
    }
}

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

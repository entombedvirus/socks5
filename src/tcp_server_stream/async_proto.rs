use std::net::{Ipv4Addr, Ipv6Addr};

use tokio::{
    io::{self, AsyncReadExt},
    net::TcpStream,
};

use crate::proto;

impl proto::ClientGreeting {
    pub async fn read_from_stream(stream: &mut TcpStream) -> io::Result<Self> {
        let mut buf = [0_u8; 2];
        stream.read_exact(&mut buf).await?;
        if buf[0] != proto::SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected socks version: {}, got: {}",
                    proto::SOCKS_VERSION,
                    buf[0]
                ),
            ));
        }

        let nauth = buf[1];
        let mut auth_bytes = Vec::with_capacity(nauth as usize);
        stream
            .take(nauth as u64)
            .read_to_end(&mut auth_bytes)
            .await?;

        auth_bytes
            .into_iter()
            .map(|b| b.try_into())
            .try_collect::<Vec<proto::AuthMethod>>()
            .map(|auths| Self(auths))
    }
}

impl proto::ClientConnectionRequest {
    pub async fn read_from_stream(stream: &mut TcpStream) -> io::Result<Self> {
        let mut buf = Vec::with_capacity(32);
        stream.take(3).read_to_end(&mut buf).await?;
        if buf[0] != proto::SOCKS_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected socks version: {}, got: {}",
                    proto::SOCKS_VERSION,
                    buf[0]
                ),
            ));
        }

        if buf[2] != proto::RESERVED {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "expected reserved byte to be: {}, got: {}",
                    proto::RESERVED,
                    buf[2]
                ),
            ));
        }

        let cmd: proto::ClientCommand = buf[1].try_into()?;
        let dest_addr = proto::Address::read_from_stream(stream).await?;

        let mut buf = [0_u8; 2];
        stream.read_exact(&mut buf).await?;
        let dest_port = u16::from_be_bytes(buf);

        Ok(Self {
            cmd,
            dest_addr,
            dest_port,
        })
    }
}

impl proto::Address {
    pub async fn read_from_stream(stream: &mut TcpStream) -> io::Result<Self> {
        let mut buf = [0_u8; 255];
        stream.read_exact(&mut buf[..1]).await?;
        match buf[0] {
            0x01 => {
                stream.read_exact(&mut buf[..4]).await?;
                let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                Ok(Self::Ipv4(addr))
            }
            0x03 => {
                stream.read_exact(&mut buf[..1]).await?;
                let dn_len = buf[0] as usize;
                stream.read_exact(&mut buf[..dn_len]).await?;
                let dn = String::from_utf8(buf[..dn_len].to_vec())
                    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
                Ok(Self::DomainName(dn))
            }
            0x04 => {
                let mut buf = [0_u8; 16];
                stream.read_exact(&mut buf).await?;
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

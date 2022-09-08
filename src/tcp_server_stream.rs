use std::net::{Ipv4Addr, Ipv6Addr};

use futures::future::TryFutureExt;
use futures::prelude::*;
use tokio::{
    io::{self, copy_bidirectional, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::proto;

pub struct ClientStream {}

struct WaitingForGreeting {
    stream: TcpStream,
    greeting: proto::ClientGreeting,
}
struct WaitingForConnectRequest {
    stream: TcpStream,
}
struct ServingConnectRequest {
    stream: TcpStream,
    request: proto::ClientConnectionRequest,
}

impl ClientStream {
    pub async fn handle(stream: TcpStream) -> io::Result<()> {
        Self::read_client_greeting(stream)
            .and_then(|state| Self::choose_auth_method(state))
            .and_then(|state| Self::read_connect_request(state))
            .and_then(|state| Self::serve_connect_request(state))
            .await
    }

    async fn read_client_greeting(mut stream: TcpStream) -> io::Result<WaitingForGreeting> {
        match proto::ClientGreeting::read_from_stream(&mut stream).await {
            Ok(greeting) => Ok(WaitingForGreeting { stream, greeting }),
            Err(err) => {
                stream.write_all(&[proto::SOCKS_VERSION, 0xff]).await?;
                Err(err)
            }
        }
    }

    async fn choose_auth_method(
        WaitingForGreeting {
            mut stream,
            greeting,
        }: WaitingForGreeting,
    ) -> io::Result<WaitingForConnectRequest> {
        if greeting.0.contains(&proto::AuthMethod::NoAuth) {
            stream
                .write_all(&[proto::SOCKS_VERSION, proto::AuthMethod::NoAuth as u8])
                .await?;
            Ok(WaitingForConnectRequest { stream })
        } else {
            stream.write_all(&[proto::SOCKS_VERSION, 0xff]).await?;
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "client does not support NoAuth authentication method",
            ))
        }
    }

    async fn read_connect_request(
        WaitingForConnectRequest { mut stream }: WaitingForConnectRequest,
    ) -> io::Result<ServingConnectRequest> {
        match proto::ClientConnectionRequest::read_from_stream(&mut stream).await {
            Ok(request) => Ok(ServingConnectRequest { stream, request }),
            Err(err) => {
                let resp = proto::ServerResponse {
                    status: proto::ServerStatus::GeneralFailure,
                    bound_address: proto::EMPTY_ADDRESS,
                    bound_port: 0,
                };
                stream.write_all(&resp.as_bytes()).await?;
                Err(err)
            }
        }
    }

    async fn serve_connect_request(
        ServingConnectRequest {
            mut stream,
            request,
        }: ServingConnectRequest,
    ) -> io::Result<()> {
        if request.cmd != proto::ClientCommand::EstablishConnection {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("client command is not supported: {:?}", request.cmd),
            ));
        }

        let mut dialed_conn = TcpStream::connect(format!(
            "{}:{}",
            request.dest_addr.to_ip_addr(),
            request.dest_port
        ))
        .await?;

        let resp = proto::ServerResponse {
            status: proto::ServerStatus::RequestGranted,
            bound_address: proto::EMPTY_ADDRESS,
            bound_port: 0,
        };
        stream.write_all(&resp.as_bytes()).await?;

        let (a, b) = copy_bidirectional(&mut stream, &mut dialed_conn).await?;
        eprintln!("proxied total {}, bytes", a + b);
        Ok(())
    }
}

impl proto::ClientGreeting {
    async fn read_from_stream(stream: &mut TcpStream) -> io::Result<Self> {
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

        match auth_bytes
            .into_iter()
            .map(|b| b.try_into())
            .try_collect::<Vec<proto::AuthMethod>>()
        {
            Ok(auths) => Ok(Self(auths)),
            Err(err) => Err(err),
        }
    }
}

impl proto::ClientConnectionRequest {
    async fn read_from_stream(stream: &mut TcpStream) -> io::Result<Self> {
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
    async fn read_from_stream(stream: &mut TcpStream) -> io::Result<Self> {
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

impl proto::ServerResponse {
    fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(proto::SOCKS_VERSION);
        buf.push(self.status as u8);
        buf.push(proto::RESERVED);
        buf.extend_from_slice(&self.bound_address.as_bytes());
        buf.extend_from_slice(&self.bound_port.to_be_bytes());

        buf
    }
}

impl proto::Address {
    fn as_bytes(self: &proto::Address) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            proto::Address::Ipv4(addr) => {
                buf.push(0x01);
                buf.extend_from_slice(&addr.octets());
            }
            proto::Address::DomainName(dn) => {
                buf.push(0x03);
                buf.push(dn.len() as u8);
                buf.extend_from_slice(dn.as_bytes());
            }
            proto::Address::Ipv6(addr) => {
                buf.push(0x04);
                buf.extend_from_slice(&addr.octets());
            }
        }
        buf
    }
}

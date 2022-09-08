mod async_proto;

use futures::future::TryFutureExt;
use tokio::{
    io::{self, copy_bidirectional, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use crate::proto;

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

pub async fn handle(stream: TcpStream) -> io::Result<()> {
    read_client_greeting(stream)
        .and_then(|state| choose_auth_method(state))
        .and_then(|state| read_connect_request(state))
        .and_then(|state| serve_connect_request(state))
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
    match request.cmd {
        proto::ClientCommand::EstablishConnection => {
            serve_establish_connection(stream, request).await
        }
        proto::ClientCommand::EstablishPortBinding => {
            serve_establish_port_bindings(stream, request).await
        }
        cmd => {
            let resp = proto::ServerResponse {
                status: proto::ServerStatus::CommandNotSupported,
                bound_address: proto::EMPTY_ADDRESS,
                bound_port: 0,
            };
            stream.write_all(&resp.as_bytes()).await?;
            Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("client command {cmd:?} is not supported"),
            ))
        }
    }
}

async fn serve_establish_port_bindings(
    mut stream: TcpStream,
    request: proto::ClientConnectionRequest,
) -> io::Result<()> {
    let binding = TcpListener::bind(format!(
        "{}:{}",
        request.dest_addr.to_ip_addr(),
        request.dest_port,
    ))
    .await?;
    let binding_addr = binding.local_addr()?;

    let resp = proto::ServerResponse {
        status: proto::ServerStatus::RequestGranted,
        bound_address: binding_addr.into(),
        bound_port: binding_addr.port(),
    };
    stream.write_all(&resp.as_bytes()).await?;

    let (mut incoming_stream, incoming_addr) = binding.accept().await?;
    let resp = proto::ServerResponse {
        status: proto::ServerStatus::RequestGranted,
        bound_address: incoming_addr.into(),
        bound_port: incoming_addr.port(),
    };
    stream.write_all(&resp.as_bytes()).await?;

    copy_bidirectional(&mut stream, &mut incoming_stream).await?;
    Ok(())
}

async fn serve_establish_connection(
    mut stream: TcpStream,
    request: proto::ClientConnectionRequest,
) -> io::Result<()> {
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

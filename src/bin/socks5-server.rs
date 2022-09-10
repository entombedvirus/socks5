use std::{env, io};

use socks5::tcp_server_stream;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let expected_num_args = 2;
    if env::args().len() != expected_num_args {
        eprintln!("expected {expected_num_args} got {}", env::args().len());
    }

    let addr = env::args().nth(1).unwrap_or("127.0.0.1:4242".to_owned());
    println!("server listening on {addr}");
    let lis = TcpListener::bind(addr).await?;

    loop {
        let (stream, _) = lis.accept().await?;
        tokio::spawn(async move {
            if let Err(err) = tcp_server_stream::handle(stream).await {
                eprintln!("handle_stream: {err:?}");
            }
        });
    }
}

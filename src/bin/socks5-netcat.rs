use std::{env, io, thread};

use ::socks5::proto;
use ::socks5::tcp_sock_stream;

fn main() {
    let args: Vec<_> = env::args().collect();
    let expected_num_args = 4;
    if args.len() != expected_num_args {
        eprintln!("expected {expected_num_args} got {}", args.len());
    }

    if let [_, server_addr, dest_addr, dest_port] = &args[..] {
        let mut stream_in = tcp_sock_stream::connect(tcp_sock_stream::ConnectRequest {
            server_addr: server_addr.to_owned(),
            dest_addr: dest_addr.to_owned(),
            supported_auth_methods: vec![proto::AuthMethod::NoAuth],
            dest_port: dest_port.parse().unwrap(),
        })
        .unwrap();
        let mut stream_out = stream_in.try_clone().unwrap();
        thread::spawn(move || {
            let mut stdin = io::stdin().lock();
            io::copy(&mut stdin, &mut stream_out).unwrap();
        });

        let mut stdout = io::stdout().lock();
        io::copy(&mut stream_in, &mut stdout).unwrap();
    }
}

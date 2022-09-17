use std::{
    borrow::BorrowMut,
    io,
    marker::Unpin,
    os::unix::prelude::{AsRawFd, RawFd},
    pin::Pin,
    ptr,
    task::{Context, Poll},
    thread::{self, sleep_ms},
    time::Duration,
};

use futures::{future::FusedFuture, ready, select, Future, FutureExt};
use libc;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

pub(crate) async fn splice_bidirectional(a: TcpStream, b: TcpStream) -> io::Result<()> {
    // let a = a.as_raw_fd();
    // let b = b.as_raw_fd();
    //
    // let s = SpliceBirectional {
    //     // a,
    //     // b,
    //     // a_to_b: splice_one_way(a_reader, b_writer),
    //     a_to_b: splice_one_way(a, b),
    //     b_to_a: splice_one_way(b, a),
    // };
    let mut a_to_b = splice_one_way(&a, &b)?;
    let mut b_to_a = splice_one_way(&b, &a)?;
    select! {
        res = a_to_b => {
            if let Err(err) = res {
                return Err(err);
            }
            b_to_a.await
        }
        res = b_to_a => {
            if let Err(err) = res {
                return Err(err);
            }
            a_to_b.await
        }
    }
}

macro_rules! try_libc {
    ($e: expr) => {{
        let ret = $e;
        if ret == -1 {
            return Err(io::Error::last_os_error());
        }
        ret
    }};
}

macro_rules! cvt {
    ($e:expr) => {{
        let ret = $e;
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            let ret: usize = ret.try_into().unwrap();
            Ok(ret)
        }
    }};
}

fn sys_pipe() -> io::Result<(RawFd, RawFd)> {
    let mut pipefd = [0; 2];
    try_libc!(unsafe { libc::pipe(pipefd.as_mut_ptr()) });
    for fd in &pipefd {
        let ret = try_libc!(unsafe { libc::fcntl(*fd, libc::F_GETFD) });
        try_libc!(unsafe { libc::fcntl(*fd, libc::F_SETFD, ret | libc::FD_CLOEXEC) });
        let ret = try_libc!(unsafe { libc::fcntl(*fd, libc::F_GETFL) });
        try_libc!(unsafe { libc::fcntl(*fd, libc::F_SETFL, ret | libc::O_NONBLOCK) });
    }
    Ok((pipefd[0], pipefd[1]))
}

// struct SpliceBirectional {
//     // a: &'a mut TcpStream,
//     // b: &'a mut TcpStream,
//     a_to_b: SpliceFuture,
//     b_to_a: SpliceFuture,
// }

// impl Future for SpliceBirectional {
//     type Output = io::Result<()>;

//     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         let a_to_b = Pin::new(&mut self.a_to_b).poll(cx);
//         let b_to_a = Pin::new(&mut self.b_to_a).poll(cx);
//         if a_to_b.is_pending() || b_to_a.is_pending() {
//             Poll::Pending
//         } else {
//             Poll::Ready(Ok(()))
//         }
//     }
// }

fn splice_one_way<'a>(
    reader: &'a TcpStream,
    writer: &'a TcpStream,
) -> Result<SpliceFuture<'a>, io::Error> {
    let (buf_read, buf_write) = sys_pipe()?;
    Ok(SpliceFuture {
        state: TransferState::Running,
        reader,
        writer,
        buf_read,
        buf_write,
        num_buf: 0,
        read_done: false,
    })
}

#[derive(Debug, PartialEq)]
enum TransferState {
    Running,
    Done,
}

#[derive(Debug)]
struct SpliceFuture<'a> {
    state: TransferState,
    reader: &'a TcpStream,
    writer: &'a TcpStream,
    buf_read: RawFd,
    buf_write: RawFd,
    num_buf: usize,
    read_done: bool,
}

impl<'a> SpliceFuture<'a> {
    fn splice(fd_in: RawFd, fd_out: RawFd, len: usize) -> io::Result<usize> {
        cvt!(unsafe {
            libc::splice(
                fd_in,
                ptr::null_mut(),
                fd_out,
                ptr::null_mut(),
                len,
                libc::SPLICE_F_NONBLOCK,
            )
        })
    }
}

impl<'a> Future for SpliceFuture<'a> {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        dbg!(&self);
        match self.state {
            TransferState::Done => Poll::Ready(Ok(())),
            TransferState::Running => loop {
                if !dbg!(self.read_done) {
                    let read_op = self.reader.try_io(tokio::io::Interest::READABLE, || {
                        dbg!(Self::splice(
                            self.reader.as_raw_fd(),
                            self.buf_write,
                            64 << 10
                        ))
                    });
                    match read_op {
                        Ok(n_read) => {
                            if n_read == 0 {
                                // end of input
                                self.read_done = true;
                            } else {
                                self.num_buf += n_read
                            }
                        }
                        Err(err) => {
                            if err.kind() != io::ErrorKind::WouldBlock {
                                return Poll::Ready(Err(err));
                            }
                            // read would block, fallthrough to writing
                        }
                    }
                    if self.num_buf == 0 && !self.read_done {
                        // register to wake up when reader is ready for reads
                        let op = dbg!(self.reader.poll_read_ready(cx));
                        match ready!(op) {
                            Ok(_) => continue,
                            Err(err) => return Poll::Ready(Err(err)),
                        };
                    }
                }

                if dbg!(self.num_buf == 0 && self.read_done) {
                    // no more left to read and no more left to write
                    self.state = TransferState::Done;
                    return Poll::Ready(Ok(()));
                }

                if self.num_buf > 0 {
                    let write_op = self.writer.try_io(tokio::io::Interest::WRITABLE, || {
                        dbg!(Self::splice(
                            self.buf_read,
                            self.writer.as_raw_fd(),
                            self.num_buf
                        ))
                    });
                    match write_op {
                        Ok(n_written) => {
                            self.num_buf -= n_written;
                        }
                        Err(err) => {
                            if err.kind() == io::ErrorKind::WouldBlock {
                                // register to wake up when writer is ready for writes
                                match ready!(self.writer.poll_write_ready(cx)) {
                                    Ok(_) => continue,
                                    Err(err) => return Poll::Ready(Err(err)),
                                };
                            }
                            return Poll::Ready(Err(err));
                        }
                    }
                }
            },
        }
    }
}

impl<'a> FusedFuture for SpliceFuture<'a> {
    fn is_terminated(&self) -> bool {
        self.state == TransferState::Done
    }
}

impl<'a> Drop for SpliceFuture<'a> {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.buf_read);
            libc::close(self.buf_write);
        }
    }
}

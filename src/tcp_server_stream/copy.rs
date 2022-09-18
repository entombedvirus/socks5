use std::{
    io,
    os::unix::{
        self,
        prelude::{AsRawFd, OwnedFd, RawFd},
    },
    pin::Pin,
    ptr,
    task::{Context, Poll},
};

use futures::{ready, select, Future, FutureExt};
use libc;
use tokio::{
    io::AsyncWrite,
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

pub(crate) async fn splice_bidirectional(a: TcpStream, b: TcpStream) -> io::Result<()> {
    let (a_read, a_write) = a.into_split();
    let (b_read, b_write) = b.into_split();
    let mut a_to_b = splice_one_way(a_read, b_write)?.fuse();
    let mut b_to_a = splice_one_way(b_read, a_write)?.fuse();
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

fn splice_one_way(reader: OwnedReadHalf, writer: OwnedWriteHalf) -> io::Result<SpliceFuture> {
    let (buf_read, buf_write) = sys_pipe()?;
    Ok(SpliceFuture {
        reader,
        writer,
        buf_read,
        buf_write,
        num_buf: 0,
        read_done: false,
    })
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

fn sys_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    use unix::io::FromRawFd;
    let mut pipefd = [0; 2];
    try_libc!(unsafe { libc::pipe(pipefd.as_mut_ptr()) });
    for fd in &pipefd {
        let ret = try_libc!(unsafe { libc::fcntl(*fd, libc::F_GETFD) });
        try_libc!(unsafe { libc::fcntl(*fd, libc::F_SETFD, ret | libc::FD_CLOEXEC) });
        let ret = try_libc!(unsafe { libc::fcntl(*fd, libc::F_GETFL) });
        try_libc!(unsafe { libc::fcntl(*fd, libc::F_SETFL, ret | libc::O_NONBLOCK) });
    }
    Ok((
        // safety: pipe descriptors are not shared, and require no other cleanup other than close
        unsafe { unix::io::OwnedFd::from_raw_fd(pipefd[0]) },
        unsafe { unix::io::OwnedFd::from_raw_fd(pipefd[1]) },
    ))
}

#[derive(Debug)]
struct SpliceFuture {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    buf_read: OwnedFd,
    buf_write: OwnedFd,
    num_buf: usize,
    read_done: bool,
}

impl SpliceFuture {
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

    fn do_read_op(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let read_op = self
            .reader
            .as_ref()
            .try_io(tokio::io::Interest::READABLE, || {
                dbg!(Self::splice(
                    self.reader.as_ref().as_raw_fd(),
                    self.buf_write.as_raw_fd(),
                    64 << 10
                ))
            });
        match read_op {
            Ok(nread) => {
                self.read_done = nread == 0;
                Poll::Ready(read_op)
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::WouldBlock {
                    ready!(self.reader.as_ref().poll_read_ready(cx))?;
                    Poll::Ready(Ok(0))
                } else {
                    Poll::Ready(Err(err))
                }
            }
        }
    }

    fn do_write_op(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        let write_op = self
            .writer
            .as_ref()
            .try_io(tokio::io::Interest::WRITABLE, || {
                dbg!(Self::splice(
                    self.buf_read.as_raw_fd(),
                    self.writer.as_ref().as_raw_fd(),
                    self.num_buf
                ))
            });
        match write_op {
            Ok(n_written) => Poll::Ready(Ok(n_written)),
            Err(err) => {
                if err.kind() == io::ErrorKind::WouldBlock {
                    // register to wake up when writer is ready for writes
                    ready!(self.writer.as_ref().poll_write_ready(cx))?;
                    Poll::Ready(Ok(0))
                } else {
                    Poll::Ready(Err(err))
                }
            }
        }
    }
}

impl Future for SpliceFuture {
    type Output = io::Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            while self.num_buf == 0 && !self.read_done {
                self.num_buf += ready!(self.do_read_op(cx))?;
            }

            while self.num_buf > 0 {
                self.num_buf -= ready!(self.do_write_op(cx))?;
            }

            if self.num_buf == 0 && self.read_done {
                return Pin::new(&mut self.writer).poll_shutdown(cx);
            }
        }
    }
}

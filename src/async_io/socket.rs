use async_io::Async;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io;
use std::mem::MaybeUninit;
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct AsyncSocket {
    inner: Arc<Async<Socket>>,
}

impl AsyncSocket {
    pub fn new(addr: IpAddr, socket_type: Type, protocol: Protocol) -> io::Result<AsyncSocket> {
        let socket = match addr {
            IpAddr::V4(_) => Socket::new(Domain::IPV4, socket_type, Some(protocol))?,
            IpAddr::V6(_) => Socket::new(Domain::IPV6, socket_type, Some(protocol))?,
        };
        socket.set_nonblocking(true)?;
        Ok(AsyncSocket {
            inner: Arc::new(Async::new(socket)?),
        })
    }
    pub async fn send_to(&self, buf: &mut [u8], target: &SockAddr) -> io::Result<usize> {
        loop {
            self.inner.writable().await?;
            match self
                .inner
                .write_with(|inner| inner.send_to(buf, target))
                .await
            {
                Ok(n) => return Ok(n),
                Err(_) => continue,
            }
        }
    }
    #[allow(dead_code)]
    pub async fn recv(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        loop {
            self.inner.readable().await?;
            match self.inner.read_with(|inner| inner.recv(buf)).await {
                Ok(result) => return Ok(result),
                Err(_) => continue,
            }
        }
    }
}

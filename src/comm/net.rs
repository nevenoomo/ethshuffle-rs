//! # Networking
//!
//! Module handles underlying communication between CoinShuffle participants.  

use super::messages::{Message, RelayMessage};
use super::peers::Peer;
use bincode::{self};
use std::io::{self, Read, Write};
use std::net;

/// Abstraction over the connection method. The underlying implementation
/// may use a p2p network or rely on a third party.
pub trait Connector {
    /// Send message `m` to peer `p`
    fn send_to(&mut self, p: &Peer, m: Message) -> io::Result<()>;
    /// Receive message from peer `p`
    fn recv_from(&mut self, p: &Peer) -> io::Result<Message>;
}

/// A connector to use a relay server for communicating with peers.
pub struct RelayConnector {
    stream: net::TcpStream,
}

impl RelayConnector {
    /// Creates a new `RelayConnector` instance from the given relay server address
    pub fn new(relay_addr: impl net::ToSocketAddrs) -> io::Result<Self> {
        let addr = if let Some(addr) = relay_addr.to_socket_addrs()?.next() {
            addr
        } else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relay address is not supplied",
            ));
        };
        let stream = net::TcpStream::connect(addr)?;

        Ok(RelayConnector { stream })
    }
}

impl Connector for RelayConnector {
    fn send_to(&mut self, p: &Peer, m: Message) -> io::Result<()> {
        let n = bincode::serialized_size(&m).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "could not serialize the message",
            )
        })?;

        if n > u32::MAX as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the message is too long",
            ));
        }

        let n = n as u32;
        
        let r_msg = RelayMessage::new(p.id, m);

        self.stream.write_all(&n.to_be_bytes())?;
        bincode::serialize_into(&self.stream, &r_msg)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "could not send a message"))
    }

    fn recv_from(&mut self, _: &Peer) -> io::Result<Message> {
        let mut n_buf = [0u8; 4];
        self.stream.read_exact(&mut n_buf)?;

        let n = u32::from_be_bytes(n_buf);

        let mut buf = vec![0u8; n as usize];

        self.stream.read_exact(buf.as_mut_slice())?;

        bincode::deserialize_from(buf.as_slice()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "could not deserialize the received a message",
            )
        })
    }
}

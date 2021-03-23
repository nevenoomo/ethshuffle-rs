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
    /// Receive message delivered to self from anyone.
    fn recv(&mut self) -> io::Result<Message>;
    /// Receive message from peer `p`
    fn recv_from(&mut self, p: &Peer) -> io::Result<Message>;
    /// Broadcast a given message to all peers
    fn broadcast(&mut self, ps: &Vec<Peer>, m: Message) -> io::Result<()>;
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

impl RelayConnector {
    /// Send the length of the next message to the relay server. Implements the length delimited codec
    fn send_length_header(&mut self, m: &Message) -> io::Result<()> {
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
        self.stream.write_all(&n.to_be_bytes())?;
        Ok(())
    }

    fn recv_length_header(&mut self) -> io::Result<u32> {
        // read the length of the incoming message
        let mut n_buf = [0u8; 4];
        self.stream.read_exact(&mut n_buf)?;
        let n = u32::from_be_bytes(n_buf);

        Ok(n)
    }
}

impl Connector for RelayConnector {
    fn send_to(&mut self, p: &Peer, m: Message) -> io::Result<()> {
        self.send_length_header(&m)?;

        let r_msg = RelayMessage::new(p.id, m);

        bincode::serialize_into(&self.stream, &r_msg)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "could not send a message"))
    }

    fn recv(&mut self) -> io::Result<Message> {
        let n = self.recv_length_header()?;

        // read the incoming data
        let mut buf = vec![0u8; n as usize];
        self.stream.read_exact(buf.as_mut_slice())?;

        // deserialize from the received bytes
        let r_msg: RelayMessage = bincode::deserialize_from(buf.as_slice()).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "could not deserialize the received a message",
            )
        })?;

        Ok(r_msg.msg)
    }

    fn recv_from(&mut self, _: &Peer) -> io::Result<Message> {
        self.recv()
    }

    fn broadcast(&mut self, _: &Vec<Peer>, m: Message) -> io::Result<()> {
        let broadcast_peer = Peer::broadcast_peer();
        self.send_to(&broadcast_peer, m)
    }
}

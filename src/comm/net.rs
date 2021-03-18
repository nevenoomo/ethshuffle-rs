//! # Networking
//!
//! Module handles underlying communication between CoinShuffle participants.  

use super::messages::{Message, RelayMessage};
use super::peers::Peer;
use bincode::{self, Options};
use serde::{Deserialize, Serialize};
use std::io;
use std::net;

type BincodeLimitedOpt =
    bincode::config::WithOtherLimit<bincode::DefaultOptions, bincode::config::Bounded>;
type IoReaderTcpStream = bincode::de::read::IoReader<std::net::TcpStream>;

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
    ser: bincode::Serializer<net::TcpStream, BincodeLimitedOpt>,
    de: bincode::Deserializer<IoReaderTcpStream, BincodeLimitedOpt>,
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
        // we will need to make the stream owned, so need two copies
        let stream_r = net::TcpStream::connect(addr)?;
        let stream_w = stream_r.try_clone()?;

        // by default bincode will read unlimited number of bytes, which can result in DoS
        let opt = bincode::DefaultOptions::new().with_limit(4096);

        // TODO add framing codec length_delimited
        let ser = bincode::Serializer::new(stream_r, opt);
        let de = bincode::Deserializer::with_reader(stream_w, opt);

        Ok(RelayConnector { ser, de })
    }
}

impl Connector for RelayConnector {
    fn send_to(&mut self, p: &Peer, m: Message) -> io::Result<()> {
        let r_msg = RelayMessage::new(p.id, m);
        r_msg.serialize(&mut self.ser).or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "could not receive message",
            ))
        })
    }

    fn recv_from(&mut self, _: &Peer) -> io::Result<Message> {
        Message::deserialize(&mut self.de).or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "could not receive message",
            ))
        })
    }
}


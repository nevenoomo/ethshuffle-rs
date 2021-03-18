//! # Client
//!
//! Defines the client operation for CoinShuffling

use super::net::Connector;

pub struct Client<C> {
    conn: C,
}

impl<C: Connector> Client<C> {
    /// Creates a new `Client` instance with the underlying connection `conn`.
    pub fn new(conn: C) -> Client<C> {
        Client { conn }
    }
}

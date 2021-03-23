//! # Client
//!
//! Defines the client operation for CoinShuffling

use super::net::Connector;
use super::peers::{AccountNum, Peer};

pub struct Client<C> {
    my_id: u16,
    conn: C,
    session_id: u64,
    peers: Vec<Peer>,
}

impl<C: Connector> Client<C> {
    /// Creates a new `Client` from the underlying connection, other peer *ethereum addresses*, and *self ethereum address*
    pub fn new<'a, 'b: 'a>(
        conn: C,
        session_id: u64,
        mut peer_accounts: Vec<&'a AccountNum>,
        my_account: &'b AccountNum,
    ) -> Client<C> {
        peer_accounts.push(my_account);
        let sorted = peer_accounts.sort_by_key(|p| **p);
        // safe to unwrap as the the value is definitely in the vector
        let my_id = peer_accounts
            .binary_search_by_key(my_account, |p| **p)
            .unwrap() as u16;
        let peers = peer_accounts
            .into_iter()
            .enumerate()
            .map(|(id, p)| Peer::new(id as u16, p))
            .collect();

        Client {
            my_id,
            conn,
            session_id,
            peers,
        }
    }
}

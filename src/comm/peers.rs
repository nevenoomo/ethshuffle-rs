//! # Peers
//!
//! Represents protocol peers of the given client.

use ecies_ed25519::PublicKey;
use std::cmp::Ordering;

/// Ethereum account number
pub type AccountNum = [u8; 20];

/// Represents a single shuffling participant
#[derive(Default, Clone, Eq)]
pub struct Peer {
    /// Peer's ID in the EthShuffle protocol
    pub id: u16,
    /// Peer's Ethereum Account number
    pub acc: AccountNum,
    /// Peer's CoinShuffle ephemeral key
    pub ek: PublicKey,
}

impl Ord for Peer {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl PartialOrd for Peer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Peer {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Peer {
    /// Create a new peer given its *id* and its *Ethereum account number*.
    pub fn new(id: u16, &acc: &AccountNum) -> Peer {
        Peer {
            id,
            acc,
            ek: PublicKey::default(),
        }
    }

    /// Create a new peer with the given its *id*, *Ethereum account number*, and *ephemeral public key*.
    pub fn new_with_ek(id: u16, &acc: &AccountNum, &ek: &PublicKey) -> Peer {
        Peer {
            id,
            acc,
            ek,
        }
    }

    /// Create a *broadcast peer* - a `Peer` object representing all the peers together.
    pub fn broadcast_peer() -> Peer {
        Peer::default()
    }
}

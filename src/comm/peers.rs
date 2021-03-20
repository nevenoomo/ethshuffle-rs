//! # Peers
//! 
//! Represents protocol peers of the given client.
use ed25519_dalek::PublicKey;

/// Represents a single shuffling participant
pub struct Peer {
    pub id: u32,
    pub pk: PublicKey,
}

impl Peer {
    /// Create a new peer given its *id* and its *public key*.
    pub const fn new(id: u32, pk: PublicKey) -> Peer {
        Peer { id, pk }
    }

    /// Create a *broadcast peer* - a `Peer` object representing all the peers together. 
    pub fn broadcast_peer() -> Peer {
        Peer::new(0, PublicKey::default())
    }
}

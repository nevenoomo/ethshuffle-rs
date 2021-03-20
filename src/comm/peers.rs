use ed25519_dalek::PublicKey;

/// Represents a single shuffling participant
pub struct Peer {
    pub id: u32,
    pub pk: PublicKey,
}

impl Peer {
    pub const fn new(id: u32, pk: PublicKey) -> Peer {
        Peer { id, pk }
    }

    pub fn broadcast_peer() -> Peer {
        Peer::new(0, PublicKey::default())
    }
}

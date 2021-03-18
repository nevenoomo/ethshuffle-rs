use ed25519_dalek::{PublicKey};

/// Represents a single shuffling participant
pub struct Peer {
    pub id: u32,
    pub pk: PublicKey,
}
//! # Messages
//!
//! Defines message formats used throughout the shuffling protocol.

use serde::{Deserialize, Serialize};
use ecies_ed25519::{PublicKey};

/// Generic message types
#[derive(Clone, Serialize, Deserialize)]
pub enum Message {
    /// Message for announcing the client its identifier
    AnnounceId(u16),
    /// Message for announcing ephemeral key
    AnnonceEk {
        id: u16,
        ek: PublicKey,
        session_id: u64,
        signature_v: u8,
        signature_r: [u8; 32],
        signature_s: [u8; 32],
    }
}

/// Message intended to the relaying server. In addition to the general message format
/// contains the identifier of the receiving party
#[derive(Clone, Serialize, Deserialize)]
pub struct RelayMessage {
    pub to_id: u16,
    pub msg: Message,
}

impl RelayMessage {
    /// Create a new relay message from the given generic message.
    pub fn new(to_id: u16, msg: Message) -> RelayMessage {
        RelayMessage{
            to_id,
            msg
        }
    }
}

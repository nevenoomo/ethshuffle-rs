//! # Messages
//!
//! Defines message formats used throughout the shuffling protocol.

use serde::{Deserialize, Serialize};

/// Generic message types
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum Message {
    /// Message for announcing the client its identifier
    AnnounceId(u32),
}

/// Message intended to the relaying server. In addition to the general message format
/// contains the identifier of the receiving party
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub struct RelayMessage {
    pub to_id: u32,
    pub msg: Message,
}

impl RelayMessage {
    /// Create a new relay message from the given generic message.
    pub fn new(to_id: u32, msg: Message) -> RelayMessage {
        RelayMessage{
            to_id,
            msg
        }
    }
}

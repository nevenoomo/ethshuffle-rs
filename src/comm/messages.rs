//! # Messages
//!
//! Defines message formats used throughout the shuffling protocol.

use serde::{Deserialize, Serialize};
use ecies_ed25519::{PublicKey};
use super::peers::{AccountNum, AccountNumEnc};
use std::fmt;
/// Blame reasons
#[derive(Clone, Serialize, Deserialize)]
pub enum BlameReason {
    NotEnoughBalance(u16),
    IncorrectShuffling(u16),
    IncorrectKeyExchange(u16),
}
///blame shuffling permutation information
#[derive(Clone, Serialize, Deserialize)]
pub enum BlameShuffling {
    BlameInformation{
        ad_id: u16,
        ad_perm: Vec<AccountNumEnc>,
        ad_session_id: u64,
        ad_signature_v: u8,
        ad_signature_r: [u8; 32],
        ad_signature_s: [u8; 32],        
    },
}
/// Generic message types
#[derive(Clone, Serialize, Deserialize)]
pub enum Message {
    /// Message for announcing the identifier
    AnnounceId(u16),
    /// Message for announcing ephemeral key
    AnnounceEk {
        id: u16,
        ek: PublicKey,
        session_id: u64,
        signature_v: u8,
        signature_r: [u8; 32],
        signature_s: [u8; 32],
    },
    /// Message for passing encrypted permutation of output addresses to the next peer
    Permutation {
        id: u16,
        perm: Vec<AccountNumEnc>,
        session_id: u64,
        signature_v: u8,
        signature_r: [u8; 32],
        signature_s: [u8; 32],
    },
    /// Message for run blame phase
    AnnounceBlame {
        id: u16,
        session_id: u64,
        blame_msg: BlameReason,
        signature_v: u8,
        signature_r: [u8; 32],
        signature_s: [u8; 32],
        dk: Option<[u8;32]>,
        incorrectshuffleinfo: Option<BlameShuffling>,
    },
    /// Final list of receiver addresses
    FinalList{
        last_peer_id: u16,
        last_peer_session_id: u64,
        receivers: Vec<AccountNum>,
        signature_v: u8,
        signature_r: [u8; 32],
        signature_s: [u8; 32],
    },
    /// Intermediate Message for commit phase
    CommitMsg {
        id: u16,
        senders: Vec<AccountNum>,
        receivers: Vec<AccountNum>,
        no_of_claimers: u16,
        amount: u32,
        signature_v: u8,
        signature_r: [u8; 32],
        signature_s: [u8; 32],        
    }
}
impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
       match &*self {
            Message::AnnounceEk { id, ek, session_id:_, signature_v:_, signature_r:_, signature_s:_, }=> write!(f, "AnnounceEk: id is {} ek is {:?}",id, ek.to_bytes()),
            Message::Permutation  { id:_, perm:_, session_id:_, signature_v:_, signature_r:_, signature_s:_, }=> write!(f, "Permutation"),
            Message::FinalList  { last_peer_id:_, last_peer_session_id:_, receivers:_, signature_v:_, signature_r:_, signature_s:_ }=> write!(f, "FinalList"),
           _=> write!(f, "Others"),
       }
    }
}
/// Message intended to the relaying server. In addition to the general message format
/// contains the identifier of the receiving party
#[derive(Clone, Serialize, Deserialize)]
pub struct RelayMessage {
    pub to_id: i32,
    pub from_id: u16,
    pub msg: Message,
}

impl RelayMessage {
    /// Create a new relay message from the given generic message.
    pub fn new(to_id: i32, from_id: u16, msg: Message) -> RelayMessage {
        RelayMessage{
            to_id,
            from_id,
            msg
        }
    }
}

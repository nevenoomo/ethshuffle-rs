//! # Client
//!
//! Defines the client operation for CoinShuffling

use super::errors;
use super::funccall;
use super::messages::Message;
use super::net::Connector;
use super::peers::{AccountNum, Peer};
use ecies_ed25519 as ecies;
use sha3::{Digest, Keccak256};
use std::collections::HashSet;
use std::io;

pub const DEFAULT_MAX_USERS: usize = 100;

pub struct Client<C> {
    my_id: u16,
    conn: C,
    session_id: u64,
    // all the peers taking part in the protocol
    peers: Vec<Peer>,
    dk: ecies::SecretKey,
    sk: ethkey::SecretKey,
    // amount to be transfered
    amount: u32,
    // List of receivers
    // use move semantics to populate
    final_list: Vec<AccountNum>,
}

impl<C: Connector> Client<C> {
    /// Creates a new `Client` from the underlying connection, other peer *ethereum addresses*,
    /// *self ethereum address*, and *own ethereum signing key*.
    pub fn new<'a, 'b: 'a>(
        conn: C,
        session_id: u64,
        mut peer_accounts: Vec<&'a AccountNum>,
        my_account: &'b AccountNum,
        sk: ethkey::SecretKey,
        amount: u32,
    ) -> Client<C> {
        // We need to derive Peer IDs from the account numbers. We use the ordering between account numbers
        // and assign a given peer an ID equal to the index of its account number in the sorted list
        // of account numbers of all peers.

        peer_accounts.push(my_account);
        peer_accounts.sort_by_key(|p| **p);
        // safe to unwrap as the the value is definitely in the vector
        let my_id = peer_accounts
            .binary_search_by_key(my_account, |p| **p)
            .unwrap() as u16;
        let mut peers: Vec<Peer> = peer_accounts
            .into_iter()
            .enumerate()
            .map(|(id, p)| Peer::new(id as u16, p))
            .collect();

        // Ephemeral key generation
        let mut rng = rand::thread_rng();
        let (dk, ek) = ecies::generate_keypair(&mut rng);

        peers[my_id as usize].ek = ek;

        Client {
            final_list: Vec::with_capacity(peers.len()),
            my_id,
            conn,
            session_id,
            peers,
            dk,
            sk,
            amount,
        }
    }

    /// Announce the per-session ephemeral encryption key to all protocol participants.
    pub fn run_announcement_phase(&mut self) -> io::Result<()> {
        self.announce_ek()?;
        self.receive_announcements()
    }

    /// Run the shuffling phase using `my_rcv` account address as the desired output.
    pub fn run_shuffle_phase(&mut self, my_rcv: &AccountNum) -> io::Result<()> {
        let prev_permutation: Vec<AccountNum> = if self.my_id == 0 {
            // the first peer does not receive any permutation
            Vec::new()
        } else {
            // TODO receive the permutation from peer my_id - 1 and strip last level of encryption
            unimplemented!("");

            let prev_peer = &self.peers[self.my_id as usize - 1];
            // TODO may need to trigger blame phase here
            let m = self.conn.recv_from(&prev_peer)?;

            let list = if let Message::Permutation {
                id,
                perm,
                session_id,
                signature_v,
                signature_r,
                signature_s,
            } = m
            {
                let signature = ethkey::Signature {
                    v: signature_v,
                    r: signature_r,
                    s: signature_s,
                };

                let mut hasher = Keccak256::new();

                perm.iter().for_each(|b| hasher.update(b));
                hasher.update(&[2u8]);
                hasher.update(session_id.to_le_bytes());

                let msg_hash = hasher.finalize();
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected permutation message",
                ));
            };
        };

        Ok(())
    }

    pub fn trigger_blame_phase(&mut self) -> io::Result<()> {
        Ok(())
    }

    pub fn verification_phase(&mut self) -> io::Result<()> {
        Ok(())
    }

    pub fn run_commit_phase(&mut self) -> io::Result<()> {
        self.sign_announce_commitmsg()
    }

    fn announce_ek(&mut self) -> io::Result<()> {
        // Announcing own ephemeral encryption key
        let ek = self.peers[self.my_id as usize].ek;
        let mut hasher = Keccak256::new();

        hasher.update(ek.as_bytes());
        // Need to add this to follow the CoinShuffle protocol specification
        hasher.update(&[1u8]);
        // NOTE we use LittleEndian representation here
        hasher.update(self.session_id.to_le_bytes());

        let hash = hasher.finalize();

        let ethkey::Signature {
            r: signature_r,
            s: signature_s,
            v: signature_v,
        } = self.sk.sign(hash.as_slice()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to sign the message: {}", e),
            )
        })?;

        let m = Message::AnnounceEk {
            id: self.my_id,
            ek,
            session_id: self.session_id,
            signature_r,
            signature_s,
            signature_v,
        };

        self.conn.broadcast(&self.peers, m)
    }

    fn check_id(&self, id: u16) -> io::Result<()> {
        // check whether we know this id
        if id as usize >= self.peers.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("peer with id {} is unknown", id),
            ));
        }

        Ok(())
    }

    fn recover_pub_key<U: generic_array::ArrayLength<u8>>(
        &self,
        hashed_msg: &generic_array::GenericArray<u8, U>,
        signature: &ethkey::Signature,
    ) -> io::Result<ethkey::PublicKey> {
        signature.recover(hashed_msg.as_slice()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("could not reconstruct the verification key of peer: {}", e),
            )
        })
    }

    fn receive_announcements(&mut self) -> io::Result<()> {
        let n = self.peers.len();
        // we will be storing ids of peers, which already announced their encryption keys
        let mut ids_announced = HashSet::with_capacity(n);
        // we know our own encryption key
        ids_announced.insert(self.my_id);

        while ids_announced.len() < n {
            // TODO add timeout on waiting
            let m = self.conn.recv()?;

            if let Message::AnnounceEk {
                id,
                ek,
                session_id,
                signature_r,
                signature_s,
                signature_v,
            } = m
            {
                self.check_id(id)?;

                let signature = ethkey::Signature {
                    r: signature_r,
                    s: signature_s,
                    v: signature_v,
                };

                let mut hasher = Keccak256::new();

                hasher.update(ek.as_bytes());
                // Need to add this to follow the CoinShuffle protocol specification
                hasher.update(&[1u8]);
                // NOTE we use LittleEndian representation here
                hasher.update(session_id.to_le_bytes());

                let hashed_msg = hasher.finalize();
                // recover the signer
                let vk = self.recover_pub_key(&hashed_msg, &signature)?;

                let derived_acc = vk.address();
                let peer_acc = self.peers[id as usize].acc;

                // check the session id
                if self.session_id != session_id {
                    return Err(errors::incorrect_session_number(session_id, derived_acc));
                }

                // the signer is not the one with the given id
                if *derived_acc != peer_acc {
                    return Err(errors::impersonalisation(derived_acc));
                }

                // verify the signature
                match vk.verify(&signature, hashed_msg.as_slice()) {
                    Ok(valid) if !valid => {
                        return Err(errors::signature_invalid(derived_acc));
                    }
                    Err(e) => return Err(errors::could_not_verify_signature(e, derived_acc)),
                    _ => (),
                }

                // we have already received a different key for this id
                if !ids_announced.insert(id) && self.peers[id as usize].ek != ek {
                    return Err(errors::equivocation_attempt(derived_acc));
                }
                self.peers[id as usize].ek = ek;
            }
        }

        Ok(())
    }
    fn sign_announce_commitmsg(&mut self) -> io::Result<()> {
        let mut hasher = Keccak256::new();
        let receivers = self.final_list.clone();

        for receiver in receivers.iter() {
            hasher.update(receiver);
        }

        let hash = hasher.finalize();

        let ethkey::Signature {
            r: signature_r,
            s: signature_s,
            v: signature_v,
        } = self.sk.sign(hash.as_slice()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to sign the message: {}", e),
            )
        })?;

        let senders = self.peers.iter().map(|p| p.acc.clone()).collect();

        let m = Message::CommitMsg {
            senders,
            receivers,
            no_of_claimers: self.peers.len() as u16,
            amount: self.amount,
            signature_v,
            signature_r,
            signature_s,
        };

        self.conn.broadcast(&self.peers, m)
    }
}

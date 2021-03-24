//! # Client
//!
//! Defines the client operation for CoinShuffling

use super::messages::Message;
use super::net::Connector;
use super::peers::{AccountNum, Peer};
use ecies_ed25519 as ecies;
use sha3::{Digest, Keccak256};
use std::collections::HashSet;
use std::io;

pub struct Client<C> {
    my_id: u16,
    conn: C,
    session_id: u64,
    peers: Vec<Peer>,
    dk: ecies::SecretKey,
    sk: ethkey::SecretKey,
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
            my_id,
            conn,
            session_id,
            peers,
            dk,
            sk,
        }
    }

    pub fn run_announcement_phase(&mut self) -> io::Result<()> {
        self.announce_ek()?;
        self.receive_announcements()
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
                // check whether we know this id
                if id as usize >= self.peers.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("peer with id {} is unknown", id),
                    ));
                }

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
                let vk = signature.recover(hashed_msg.as_slice()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("could not reconstruct the verification key of peer: {}", e),
                    )
                })?;

                let derived_acc = vk.address();
                let peer_acc = self.peers[id as usize].acc;

                // check the session id
                if self.session_id != session_id {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "peer used incorrect session number {}\nBlame account number: {:x?}",
                            session_id, derived_acc
                        ),
                    ));
                }

                // the signer is not the one with the given id
                if *derived_acc != peer_acc {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("impersonalisation attempt by {:x?}", derived_acc),
                    ));
                }

                // verify the signature
                match vk.verify(&signature, hashed_msg.as_slice()) {
                    Ok(valid) if !valid => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "signature is invalid\nBlame account number: {:x?}",
                                derived_acc
                            ),
                        ))
                    }
                    Err(e) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "signature validation failed: {}\nBlame account number: {:x?}",
                                e, derived_acc
                            ),
                        ))
                    }
                    _ => (),
                }

                // we have already received a key for this id
                if ids_announced.insert(id) {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("key already received from {:x?}", derived_acc),
                    ));
                }
                self.peers[id as usize].ek = ek;
            }
        }

        Ok(())
    }
}

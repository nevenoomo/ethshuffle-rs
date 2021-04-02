//! # Client
//!
//! Defines the client operation for CoinShuffling

use super::errors;
use super::funccall::{lookup_balance_byaddr_and_check, lookup_ek_byaddr_and_check, transferfunc, updateek};
use super::messages::{BlameReason, BlameShuffling, Message};
use super::net::Connector;
use super::peers::{AccountNum, AccountNumEnc, Peer};
use ecies_ed25519 as ecies;
use rand::{self, seq::SliceRandom};
use sha3::{Digest, Keccak256};
use std::collections::HashSet;
use std::convert::TryInto;
use std::io;
//for contract call
use tokio2::runtime::Runtime;
use web3::types::U256;

pub const DEFAULT_MAX_USERS: usize = 100;

pub struct CommitmsgPrepare {
    //List of receivers
    final_list: Vec<AccountNum>,
    //Signitures for each pair same order as peers
    signatures_v: Vec<u8>,
    signatures_r: Vec<[u8; 32]>,
    signatures_s: Vec<[u8; 32]>,
}

pub struct Client<C> {
    my_id: u16,
    conn: C,
    session_id: u64,
    // all the peers taking part in the protocol
    peers: Vec<Peer>,
    dk: ecies::SecretKey,
    sk: ethkey::SecretKey,
    // The commiter who commit the transaction: the hoster
    commiter: AccountNum,
    // Contract address
    contract_address: AccountNum,
    // Contract abi json file in path
    abi: String,
    // amount to be transfered
    amount: u32,
    // commit message to be committed to the chain
    commitmsg: CommitmsgPrepare,
}

impl<C: Connector> Client<C> {
    // FIXME update documentation
    // FIXME should not have so many arguments!! Use structures to bring together related 
    // arguments (for example, create a contract structure to hold `abi` and `contract_address`)

    /// Creates a new `Client` from the underlying connection, other peer *ethereum addresses*,
    /// *self ethereum address*, and *own ethereum signing key*.
    pub fn new<'a, 'b: 'a>(
        mut conn: C,
        session_id: u64,
        mut peer_accounts: Vec<&'a AccountNum>,
        my_account: &'b AccountNum,
        sk: ethkey::SecretKey,
        commiter: AccountNum,
        contract_address: AccountNum,
        abi: String,
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

        //update ek to contract
        let mut rt = Runtime::new().unwrap();
        rt.block_on(updateek(
            *my_account,
            contract_address,
            abi.clone(),
            commiter,
            U256::from(ek.to_bytes()),
        ))
        .unwrap();        

        peers[my_id as usize].ek = ek;
        conn.set_id(my_id);

        Client {
            my_id,
            conn,
            session_id,
            peers,
            dk,
            sk,
            commiter,
            contract_address,
            abi,
            amount,
            commitmsg: CommitmsgPrepare {
                final_list: vec![],
                signatures_v: vec![],
                signatures_r: vec![],
                signatures_s: vec![],
            },
        }
    }

    /// Announce the per-session ephemeral encryption key to all protocol participants.
    pub fn run_announcement_phase(&mut self) -> io::Result<()> {
        self.announce_ek()?;
        self.receive_announcements()
    }

    /// Run the shuffling phase using `my_rcv` account address as the desired output.
    pub fn run_shuffle_phase(&mut self, my_rcv: &AccountNum) -> io::Result<()> {
        let prev_permutation: Vec<AccountNumEnc> = if self.my_id == 0 {
            // the first peer does not receive any permutation
            Vec::new()
        } else {
            let prev_peer = &self.peers[self.my_id as usize - 1];
            // TODO may need to trigger blame phase here
            let m = self.conn.recv_from(&prev_peer)?;

            if let Message::Permutation {
                id,
                perm,
                session_id,
                signature_v,
                signature_r,
                signature_s,
            } = m
            {
                let shuffle_msg = BlameShuffling::BlameInformation{
                    ad_id: id,
                    ad_perm: perm.clone(),
                    ad_session_id: session_id,
                    ad_signature_v: signature_v,
                    ad_signature_r: signature_r.clone(),
                    ad_signature_s: signature_s.clone(),                       
                };
                if id != prev_peer.id {
                    self.trigger_blame_phase(BlameReason::IncorrectShuffling(id as u16), Some(shuffle_msg))?;
                    return Err(errors::unexpected_peer_id(id));
                }
                //Here is for testing for blame phase
                // if id == 1 {
                //     self.trigger_blame_phase(BlameReason::IncorrectShuffling(id as u16), Some(shuffle_msg.clone()))?;
                //     return Err(errors::unexpected_peer_id(id));
                // }
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

                // FIXME Repetitive code
                let vk = self.recover_pub_key(&msg_hash, &signature)?;

                let derived_acc = vk.address();
                let peer_acc = self.peers[id as usize].acc;

                // check the session id
                if self.session_id != session_id {
                    self.trigger_blame_phase(BlameReason::IncorrectShuffling(id as u16), Some(shuffle_msg))?;
                    return Err(errors::incorrect_session_number(session_id, derived_acc));
                }

                // the signer is not the one with the given id
                if *derived_acc != peer_acc {
                    self.trigger_blame_phase(BlameReason::IncorrectShuffling(id as u16), Some(shuffle_msg))?;
                    return Err(errors::impersonalisation(derived_acc));
                }

                // verify the signature
                match vk.verify(&signature, msg_hash.as_slice()) {
                    Ok(valid) if !valid => {
                        self.trigger_blame_phase(BlameReason::IncorrectShuffling(id as u16), Some(shuffle_msg))?;
                        return Err(errors::signature_invalid(derived_acc));
                    }
                    Err(e) => {
                        self.trigger_blame_phase(BlameReason::IncorrectShuffling(id as u16), Some(shuffle_msg))?;
                        return Err(errors::could_not_verify_signature(e, derived_acc));
                    },
                    _ => (),
                }
                perm
            } else {
                self.run_blame_phase(m)?;
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Blame phase enterred! Please restart the shuffling excluding the possible adversary",
                ));
            }
        };

        // strip the last encryption layer. note that for the first peer this will be an empty vector
        // TODO trigger blame phase on failed decryption
        let mut permutation: Vec<AccountNumEnc> = prev_permutation
            .into_iter()
            .map(|acc| ecies::decrypt(&self.dk, &acc))
            .collect::<Result<Vec<AccountNumEnc>, ecies::Error>>()
            .map_err(errors::decryption_failure)?;

        let mut rng = rand::thread_rng();

        // note that by using skip, we make sure the last peer does not actually encrypts its output
        let my_output = self
            .peers
            .iter()
            .skip(self.my_id as usize + 1)
            .map(|p| p.ek)
            .rev()
            .try_fold(Vec::from(*my_rcv), |accum, ek| {
                ecies::encrypt(&ek, &accum[..], &mut rng)
            })
            .map_err(errors::encryption_failure)?;

        permutation.push(my_output);

        permutation.shuffle(&mut rng);

        let mut hasher = Keccak256::new();

        permutation.iter().for_each(|x| hasher.update(x));
        // if I am not the last user, then I would still be in the second state
        let phase_id = if (self.my_id as usize) < self.peers.len() - 1 {
            2u8
        } else {
            3u8
        };
        hasher.update(&[phase_id]);
        hasher.update(self.session_id.to_le_bytes());

        let msg_hash = hasher.finalize();
        let ethkey::Signature {
            r: signature_r,
            s: signature_s,
            v: signature_v,
        } = self
            .sk
            .sign(msg_hash.as_slice())
            .map_err(errors::could_not_sign)?;

        // if I am not the last peer
        if (self.my_id as usize) < self.peers.len() - 1 {
            let next_peer = &self.peers[self.my_id as usize + 1];
            let m = Message::Permutation {
                id: self.my_id,
                perm: permutation,
                session_id: self.session_id,
                signature_v,
                signature_r,
                signature_s,
            };

            self.conn.send_to(&next_peer, m)?;
            // TODO trigger blame phase
            let final_list_msg = self.conn.recv()?;

            if let Message::FinalList {
                last_peer_id,
                last_peer_session_id,
                receivers,
                signature_v,
                signature_r,
                signature_s,
            } = final_list_msg
            {
                self.check_final_list(
                    last_peer_id,
                    last_peer_session_id,
                    &receivers,
                    signature_v,
                    &signature_r,
                    &signature_s,
                )?;

                self.commitmsg.final_list = receivers;
            } else {
                self.run_blame_phase(final_list_msg)?
            }
        } else {
            let final_permutation = permutation
                .into_iter()
                .map(|v| v.try_into())
                .collect::<Result<Vec<AccountNum>, _>>()
                // TODO trigger blame phase
                .map_err(|_| errors::corrupted_final_permutation())?;
            self.commitmsg.final_list = final_permutation.clone();
            let final_list = Message::FinalList {
                last_peer_session_id: self.session_id,
                last_peer_id: self.my_id,
                receivers: final_permutation.clone(),
                signature_v,
                signature_r,
                signature_s,
            };

            self.conn
                .broadcast(&self.peers[..self.peers.len() - 1], final_list)?;
        }

        Ok(())
    }

    fn check_final_list(
        &mut self,
        id: u16,
        session_id: u64,
        receivers: &Vec<AccountNum>,
        signature_v: u8,
        signature_r: &[u8; 32],
        signature_s: &[u8; 32],
    ) -> io::Result<()> {
        let last_peer = &self.peers[self.peers.len() - 1];

        if id != last_peer.id {
            return Err(errors::unexpected_peer_id(id));
        }

        let signature = ethkey::Signature {
            v: signature_v,
            r: *signature_r,
            s: *signature_s,
        };

        let mut hasher = Keccak256::new();

        receivers.iter().for_each(|b| hasher.update(b));
        hasher.update(&[3u8]);
        hasher.update(session_id.to_le_bytes());

        let msg_hash = hasher.finalize();

        let vk = self.recover_pub_key(&msg_hash, &signature)?;

        let derived_acc = vk.address();
        let peer_acc = last_peer.acc;

        // check the session id
        if self.session_id != session_id {
            return Err(errors::incorrect_session_number(session_id, derived_acc));
        }

        // the signer is not the one with the given id
        if *derived_acc != peer_acc {
            return Err(errors::impersonalisation(derived_acc));
        }

        // verify the signature
        match vk.verify(&signature, msg_hash.as_slice()) {
            Ok(valid) if !valid => Err(errors::signature_invalid(derived_acc)),
            Err(e) => Err(errors::could_not_verify_signature(e, derived_acc)),
            _ => Ok(()),
        }
    }

    pub fn trigger_blame_phase(
        &mut self,
        msg: BlameReason,
        shuffleinfo: Option<BlameShuffling>,
    ) -> io::Result<()> {
        if let BlameReason::NotEnoughBalance(adversary_id) = msg {
            let mut hasher = Keccak256::new();
            hasher.update(self.my_id.to_le_bytes());
            hasher.update(self.session_id.to_le_bytes());
            hasher.update(adversary_id.to_le_bytes());
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

            let m = Message::AnnounceBlame {
                id: self.my_id,
                session_id: self.session_id,
                blame_msg: msg,
                signature_v,
                signature_r,
                signature_s,
                dk: None,
                incorrectshuffleinfo: None,
            };
            self.conn.broadcast(&self.peers, m)?;
            println!(
                "Peer address {:?} doesn't have enough balance in contract",
                self.peers[adversary_id as usize].acc
            );
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "The blame message is broadcasted. Quit now ...",
            ))
        } else if let BlameReason::IncorrectKeyExchange(adversary_id) = msg {
            let mut hasher = Keccak256::new();
            hasher.update(self.my_id.to_le_bytes());
            hasher.update(self.session_id.to_le_bytes());
            hasher.update(adversary_id.to_le_bytes());
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

            let m = Message::AnnounceBlame {
                id: self.my_id,
                session_id: self.session_id,
                blame_msg: msg,
                signature_v,
                signature_r,
                signature_s,
                dk: None,
                incorrectshuffleinfo: None,
            };

            self.conn.broadcast(&self.peers, m)?;
            println!(
                "Peer address {:?} doesn't send correct dnc key in contract",
                self.peers[adversary_id as usize].acc
            );
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "The blame message is broadcasted. Quit now ...",
            ))
        } else if let BlameReason::IncorrectShuffling(adversary_id) = msg {
            let BlameShuffling::BlameInformation {
                ad_id,
                ad_perm,
                ad_session_id,
                ad_signature_v,
                ad_signature_r,
                ad_signature_s,
            } = shuffleinfo.unwrap();
            let mut hasher = Keccak256::new();
            hasher.update(self.my_id.to_le_bytes());
            hasher.update(self.session_id.to_le_bytes());
            hasher.update(adversary_id.to_le_bytes());
            hasher.update(self.dk.to_bytes());
            ad_perm.iter().for_each(|x| hasher.update(x));
            hasher.update(ad_session_id.to_le_bytes());
            hasher.update(ad_signature_v.to_le_bytes());
            hasher.update(ad_signature_r);
            hasher.update(ad_signature_s);
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

            let m = Message::AnnounceBlame {
                id: self.my_id,
                session_id: self.session_id,
                blame_msg: msg,
                signature_v,
                signature_r,
                signature_s,
                dk: Some(self.dk.to_bytes()),
                incorrectshuffleinfo: Some(BlameShuffling::BlameInformation {
                    ad_id,
                    ad_perm,
                    ad_session_id,
                    ad_signature_v,
                    ad_signature_r,
                    ad_signature_s,
                }),
            };
            self.conn.broadcast(&self.peers, m)?;
            println!(
                "Peer address {:?} sends incorrect Shuffle message",
                self.peers[adversary_id as usize].acc
            );
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Incorrect Shuffle message from the previous peers. Dnc key is broadcasted. Quit now ...",
            ))
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected blame message",
            ))
        }
    }

    pub fn run_blame_phase(&mut self, m: Message) -> io::Result<()> {
        if let Message::AnnounceBlame {
            id,
            session_id,
            blame_msg,
            signature_v,
            signature_r,
            signature_s,
            dk,
            incorrectshuffleinfo,
        } = m
        {
            // check whether we know this id
            if id as usize >= self.peers.len() {
                return Err(errors::unexpected_peer_id(id));
            }

            let signature = ethkey::Signature {
                r: signature_r,
                s: signature_s,
                v: signature_v,
            };

            let mut hasher = Keccak256::new();

            hasher.update(id.to_le_bytes());
            hasher.update(session_id.to_le_bytes());

            let peerincorrectshuffleinfo = incorrectshuffleinfo.unwrap();
            if let BlameReason::NotEnoughBalance(adversary_id) = blame_msg {
                hasher.update(adversary_id.to_le_bytes());
            } else if let BlameReason::IncorrectKeyExchange(adversary_id) = blame_msg {
                hasher.update(adversary_id.to_le_bytes());
            } else if let BlameReason::IncorrectShuffling(adversary_id) = blame_msg {
                hasher.update(adversary_id.to_le_bytes());
                let BlameShuffling::BlameInformation {
                    ad_id: _,
                    ref ad_perm,
                    ad_session_id,
                    ad_signature_v,
                    ad_signature_r,
                    ad_signature_s,
                } = peerincorrectshuffleinfo;
                hasher.update(dk.unwrap());
                ad_perm.iter().for_each(|x| hasher.update(x));
                hasher.update(ad_session_id.to_le_bytes());
                hasher.update(ad_signature_v.to_le_bytes());
                hasher.update(ad_signature_r);
                hasher.update(ad_signature_s);
            }

            let hashed_msg = hasher.finalize();
            // recover the signer
            let vk = self.recover_pub_key(&hashed_msg, &signature)?;

            let derived_acc = vk.address();
            let peer_acc = self.peers[id as usize].acc;

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
            if let BlameReason::NotEnoughBalance(adversary_id) = blame_msg {
                let mut rt = Runtime::new().unwrap();
                rt.block_on(lookup_balance_byaddr_and_check(
                    self.contract_address,
                    self.abi.clone(),
                    self.commiter,
                    self.peers[adversary_id as usize].acc,
                    self.amount,
                ))
                .unwrap();
            } else if let BlameReason::IncorrectKeyExchange(adversary_id) = blame_msg {
                let mut rt = Runtime::new().unwrap();
                rt.block_on(lookup_ek_byaddr_and_check(
                    self.contract_address,
                    self.abi.clone(),
                    self.commiter,
                    self.peers[adversary_id as usize].acc,
                    U256::from(self.peers[adversary_id as usize].ek.to_bytes()),
                ))
                .unwrap();
            } else if let BlameReason::IncorrectShuffling(adversary_id) = blame_msg {
                let peerincorrectshuffleinfo2 = peerincorrectshuffleinfo.clone();
                let BlameShuffling::BlameInformation {
                    ad_id,
                    ad_perm,
                    ad_session_id,
                    ad_signature_v,
                    ad_signature_r,
                    ad_signature_s,
                } = peerincorrectshuffleinfo2;
                if (ad_id as usize) != (id as usize - 1) {
                    println!(
                        "Peer address {:?} sends incorrect Shuffle message",
                        self.peers[adversary_id as usize].acc
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Incorrect Shuffle message from the previous peers. Quit now ...",
                    ));
                }

                let signature = ethkey::Signature {
                    v: ad_signature_v,
                    r: ad_signature_r,
                    s: ad_signature_s,
                };

                let mut hasher = Keccak256::new();

                let phase_id = if (ad_id as usize) < self.peers.len() - 1 {
                    2u8
                } else {
                    3u8
                };

                ad_perm.iter().for_each(|b| hasher.update(b));
                hasher.update(&[phase_id]);
                hasher.update(ad_session_id.to_le_bytes());

                let msg_hash = hasher.finalize();

                // FIXME Repetitive code
                let vk = self.recover_pub_key(&msg_hash, &signature)?;

                let derived_acc = vk.address();
                let peer_acc = self.peers[adversary_id as usize].acc;

                // check the session id
                if session_id != ad_session_id {
                    println!(
                        "Peer address {:?} sends incorrect Shuffle message",
                        self.peers[adversary_id as usize].acc
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Incorrect Shuffle message from the previous peers. Quit now ...",
                    ));
                }

                // the signer is not the one with the given id
                if *derived_acc != peer_acc {
                    println!(
                        "Peer address {:?} sends incorrect Shuffle message",
                        self.peers[adversary_id as usize].acc
                    );
                    return Err(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "Incorrect Shuffle message from the previous peers. Quit now ...",
                    ));
                }

                // verify the signature
                match vk.verify(&signature, msg_hash.as_slice()) {
                    Ok(valid) if !valid => {
                        println!(
                            "Peer address {:?} sends incorrect Shuffle message",
                            self.peers[adversary_id as usize].acc
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "Incorrect Shuffle message from the previous peers. Quit now ...",
                        ));
                    }
                    Err(_) => {
                        println!(
                            "Peer address {:?} sends incorrect Shuffle message",
                            self.peers[adversary_id as usize].acc
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "Incorrect Shuffle message from the previous peers. Quit now ...",
                        ));
                    }
                    _ => (),
                }
            }
            println!(
                "Peer address {:?} sends incorrect blame message",
                self.peers[id as usize].acc
            );
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "Incorrect blame message. Quit now ...",
            ));
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected blame message",
            ))
        }
    }

    pub fn verification_phase(&mut self) -> io::Result<()> {
        self.run_commit_phase(self.commiter, self.contract_address, self.abi.clone())?;
        Ok(())
    }
    pub fn run_commit_phase(
        &mut self,
        commiter: AccountNum,
        contract_address: AccountNum,
        abi: String,
    ) -> io::Result<()> {
        self.commitmsg.signatures_v = vec![0_u8; self.peers.len()];
        self.commitmsg.signatures_r = vec![[0_u8; 32]; self.peers.len()];
        self.commitmsg.signatures_s = vec![[0_u8; 32]; self.peers.len()];
        self.sign_announce_commitmsg()?;
        self.receive_commitmsg()?;
        //The hoster commit the transaction
        self.commit(commiter, contract_address, abi)
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
        } = self
            .sk
            .sign(hash.as_slice())
            .map_err(errors::could_not_sign)?;

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
                // check whether we know this id
                if id as usize >= self.peers.len() {
                    return Err(errors::unexpected_peer_id(id));
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
                // Check ek matches the one on the contract.
                // If not, trigger blame phase
                let mut rt = Runtime::new().unwrap();
                match rt.block_on(lookup_ek_byaddr_and_check(
                    self.contract_address,
                    self.abi.clone(),
                    self.commiter,
                    self.peers[id as usize].acc,
                    U256::from(ek.to_bytes()),
                )) {
                    Ok(_) => {self.peers[id as usize].ek = ek;}
                    Err(_) => {self.trigger_blame_phase(BlameReason::IncorrectKeyExchange(id), None)?;}
                }
            }else {
                self.run_blame_phase(m)?;
            }
        }

        Ok(())
    }
    fn sign_announce_commitmsg(&mut self) -> io::Result<()> {
        let mut hasher = Keccak256::new();
        let senders: Vec<AccountNum> = self.peers.iter().map(|p| p.acc).collect();
        let receivers = self.commitmsg.final_list.clone();
        let no_of_claimers = self.peers.len() as u16;
        for i in &senders {
            hasher.update(i);
        }
        for i in &receivers {
            hasher.update(i);
        }
        hasher.update(no_of_claimers.to_be_bytes());
        hasher.update(self.amount.to_be_bytes());
        let hash = hasher.finalize();

        let ethkey::prelude::Signature {
            r: signature_r,
            s: signature_s,
            v: signature_v,
        } = self.sk.sign(hash.as_slice()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("failed to sign the message: {}", e),
            )
        })?;

        self.commitmsg.signatures_v[self.my_id as usize] = signature_v;
        self.commitmsg.signatures_r[self.my_id as usize] = signature_r;
        self.commitmsg.signatures_s[self.my_id as usize] = signature_s;

        let m = Message::CommitMsg {
            id: self.my_id,
            senders,
            receivers,
            no_of_claimers,
            amount: self.amount,
            signature_v,
            signature_r,
            signature_s,
        };

        self.conn.broadcast(&self.peers, m)
    }

    fn receive_commitmsg(&mut self) -> io::Result<()> {
        let n = self.peers.len();
        let mut valid_insert_times = 0;
        while valid_insert_times < n - 1 {
            // TODO add timeout on waiting
            let m = self.conn.recv()?;

            if let Message::CommitMsg {
                id,
                senders,
                receivers,
                no_of_claimers,
                amount,
                signature_v,
                signature_r,
                signature_s,
            } = m
            {
                // check whether we know this id
                if id as usize >= self.peers.len() {
                    return Err(errors::unexpected_peer_id(id));
                }

                let signature = ethkey::prelude::Signature {
                    r: signature_r,
                    s: signature_s,
                    v: signature_v,
                };

                let mut hasher = Keccak256::new();

                for i in &senders {
                    hasher.update(i);
                }
                for i in &receivers {
                    hasher.update(i);
                }
                hasher.update(no_of_claimers.to_be_bytes());
                hasher.update(amount.to_be_bytes());

                let hashed_msg = hasher.finalize();
                // recover the signer
                let vk = self.recover_pub_key(&hashed_msg, &signature)?;

                let derived_acc = vk.address();
                let peer_acc = self.peers[id as usize].acc;

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

                // we have already received a different key for this id
                if self.commitmsg.signatures_v[id as usize] != 0_u8 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("key already received from {:x?}", derived_acc),
                    ));
                } else {
                    self.commitmsg.signatures_v[id as usize] = signature_v;
                    self.commitmsg.signatures_r[id as usize] = signature_r;
                    self.commitmsg.signatures_s[id as usize] = signature_s;
                    valid_insert_times += 1;
                }
                //Here is the beginning of verification phase.
                //Check every peers ETH balance is enought or not.
                //If not, trigger blame phase
                let mut rt = Runtime::new().unwrap();
                match rt.block_on(lookup_balance_byaddr_and_check(
                    self.contract_address,
                    self.abi.clone(),
                    self.commiter,
                    self.peers[id as usize].acc,
                    self.amount,
                )) {
                    Ok(_) => (),
                    Err(_) => {self.trigger_blame_phase(BlameReason::NotEnoughBalance(id as u16), None)?}
                }
            }else{
                self.run_blame_phase(m)?;
            } 
        }

        Ok(())
    }

    fn commit(
        &mut self,
        commiter: AccountNum,
        contract_address: AccountNum,
        abi: String,
    ) -> io::Result<()> {
        let matching = self.peers[self.my_id as usize].acc.iter().zip(commiter.iter()).filter(|&(a, b)| a == b).count();
        if matching == self.peers[self.my_id as usize].acc.len() && matching == commiter.len() {
            let senders: Vec<[u8; 20]> = self.peers.iter().map(|i| i.acc).collect();
            let receivers: Vec<[u8; 20]> = self.commitmsg.final_list.clone();
            let noofclaimers = self.commitmsg.final_list.len() as u128;
            let amount = self.amount;
            let v: Vec<u8> = self.commitmsg.signatures_v.clone();
            let r: Vec<U256> = self
                .commitmsg
                .signatures_r
                .clone()
                .iter()
                .map(|i| U256::from_big_endian(i))
                .collect();
            let s: Vec<U256> = self
                .commitmsg
                .signatures_s
                .clone()
                .iter()
                .map(|i| U256::from_big_endian(i))
                .collect();
            let mut rt = Runtime::new().unwrap();
            rt.block_on(transferfunc(
                commiter,
                contract_address,
                abi,
                senders,
                receivers,
                noofclaimers,
                amount,
                v,
                r,
                s,
            ))
            .unwrap();
        }else{
            println!("Wait hoster to send the final transaction...");
        }
        Ok(())
    }
}

#[test]
fn first_client_test() {
    use super::{net::RelayConnector, peers::AccountNum};
    use std::net::{SocketAddr};
    use ethkey::{SecretKey};
    use super::funccall::{check_receiver_balance};
    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    let conn = RelayConnector::new(addr).unwrap();
    use tokio2::runtime::Runtime;

    let mut client = Client::new(
        conn,
        2345 as u64,
        vec![&[0x44,0xde,0x1f,0xaA,0xa2,0xFc,0x62,0x27,0x05,0x00,0xBe,0xA1,0xde,0x45,0x71,0x6f,0xf3,0x2F,0xc9,0x45],
        &[0x0D,0x1e,0x34,0x36,0xfe,0xB9,0xe4,0x84,0x30,0x43,0xc3,0x1B,0x17,0xC3,0x95,0xA4,0x61,0x0e,0x00,0x60]],
        &[0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
        SecretKey::from_raw(&[0x2c,0x2a,0x68,0x71,0xe7,0xe2,0xcd,0x26,0x26,0xf9,0x7a,0xcc,0x7b,0xd7,0xfc,0xba,0x9a,0x27,0x50,0x0f,0xaf,0x93,0x16,0x5f,0xdc,0x66,0x20,0xef,0x0c,0x33,0xc9,0x44]).unwrap(),
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
        [238, 50, 245, 211, 24, 183, 155, 77, 119, 157, 219, 123, 251, 69, 118, 145, 249, 18, 187, 246],
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        0xFF as u32,
    );

    client.run_announcement_phase().unwrap();
    for i in 0..client.peers.len() {
        println!("peer ek: {:?}", client.peers[i].ek.to_bytes());
    }
    let recvaddr: AccountNum = [0xc5,0x57,0xB5,0x3C,0xAa,0x46,0xc9,0xaA,0xE2,0x32,0x12,0x94,0xF0,0x69,0x59,0xCb,0xa7,0xe1,0x85,0x52];
    client.run_shuffle_phase(&recvaddr).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("shuffling phase failed: {}", e),
        )
    }).unwrap();
    println!("final list is : {:?}", client.commitmsg.final_list.clone());
    client.verification_phase().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("verification phase failed: {}", e),
        )
    }).unwrap();
    println!("After verification: final list is : {:?}\n v: {:?}\n r: {:?}\n s: {:?}", 
            client.commitmsg.final_list.clone(),
            client.commitmsg.signatures_v.clone(),
            client.commitmsg.signatures_r.clone(),
            client.commitmsg.signatures_s.clone(),);
    for i in 0..client.peers.len() {
        println!("sender {}: {:?}",i, client.peers[i].acc);
    }
    for i in 0..client.commitmsg.final_list.clone().len(){
        let mut rt = Runtime::new().unwrap();
        rt.block_on(check_receiver_balance(
            client.commitmsg.final_list.clone()[i],
        )).unwrap();
    }
}

#[test]
fn second_client_test() {
    use super::{net::RelayConnector, peers::AccountNum};
    use std::net::{SocketAddr};
    use ethkey::{SecretKey};

    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    let conn = RelayConnector::new(addr).unwrap();

    let mut client = Client::new(
        conn,
        2345 as u64,
        vec![&[0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
        &[0x0D,0x1e,0x34,0x36,0xfe,0xB9,0xe4,0x84,0x30,0x43,0xc3,0x1B,0x17,0xC3,0x95,0xA4,0x61,0x0e,0x00,0x60]],
        &[0x44,0xde,0x1f,0xaA,0xa2,0xFc,0x62,0x27,0x05,0x00,0xBe,0xA1,0xde,0x45,0x71,0x6f,0xf3,0x2F,0xc9,0x45],
        SecretKey::from_raw(&[0xaa,0x77,0x02,0x2b,0x60,0xd5,0xe5,0x11,0xe7,0xc3,0xf3,0xa0,0x20,0x13,0xd9,0xb3,0x5b,0x5c,0x95,0xc0,0xce,0x75,0x3e,0xf6,0x63,0xc6,0xd8,0xdc,0xc8,0xf7,0x61,0xf9]).unwrap(),
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
        [238, 50, 245, 211, 24, 183, 155, 77, 119, 157, 219, 123, 251, 69, 118, 145, 249, 18, 187, 246],
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        0xFF as u32,
    );

    client.run_announcement_phase().unwrap();
    for i in 0..client.peers.len() {
        println!("peer ek: {:?}", client.peers[i].ek.to_bytes());
    }
    let recvaddr: AccountNum = [0x9D,0x4c,0x42,0xcd,0xE9,0x74,0xA2,0xdF,0x22,0xDF,0x71,0x03,0xB7,0x46,0x9f,0xdb,0x28,0xe0,0x06,0xA6];
    client.run_shuffle_phase(&recvaddr).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("shuffling phase failed: {}", e),
        )
    }).unwrap();
    println!("final list is : {:?}", client.commitmsg.final_list.clone());
    client.verification_phase().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("verification phase failed: {}", e),
        )
    }).unwrap();
    println!("After verification: final list is : {:?}\n v: {:?}\n r: {:?}\n s: {:?}", 
            client.commitmsg.final_list.clone(),
            client.commitmsg.signatures_v.clone(),
            client.commitmsg.signatures_r.clone(),
            client.commitmsg.signatures_s.clone(),);
    for i in 0..client.peers.len() {
        println!("sender {}: {:?}",i, client.peers[i].acc);
    }
}

#[test]
fn third_client_test() {
    use super::{net::RelayConnector, peers::AccountNum};
    use std::net::{SocketAddr};
    use ethkey::{SecretKey};

    let addr = SocketAddr::from(([127, 0, 0, 1], 5000));
    let conn = RelayConnector::new(addr).unwrap();

    let mut client = Client::new(
        conn,

        2345 as u64,

        vec![&[0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
        &[0x44,0xde,0x1f,0xaA,0xa2,0xFc,0x62,0x27,0x05,0x00,0xBe,0xA1,0xde,0x45,0x71,0x6f,0xf3,0x2F,0xc9,0x45]],

        &[0x0D,0x1e,0x34,0x36,0xfe,0xB9,0xe4,0x84,0x30,0x43,0xc3,0x1B,0x17,0xC3,0x95,0xA4,0x61,0x0e,0x00,0x60],
        SecretKey::from_raw(&[0xbd,0xe7,0x9c,0x6f,0x43,0xec,0xc0,0xda,0x74,0x56,0xba,0x7d,0x48,0x1a,0xed,0x1e,0x17,0x67,0xf6,0xde,0x73,0x98,0x4f,0x7a,0xa9,0xea,0x42,0x3a,0x8e,0xbd,0x8c,0x29]).unwrap(),

        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
        [238, 50, 245, 211, 24, 183, 155, 77, 119, 157, 219, 123, 251, 69, 118, 145, 249, 18, 187, 246],
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        0xFF as u32,
    );

    client.run_announcement_phase().unwrap();
    for i in 0..client.peers.len() {
        println!("peer ek: {:?}", client.peers[i].ek.to_bytes());
    }
    let recvaddr: AccountNum = [0xE6,0xcA,0x03,0x03,0xca,0x6B,0x6c,0x38,0x1B,0x55,0x8a,0xC4,0x3a,0x1e,0x1A,0x3B,0x71,0x4E,0xcf,0x84];
    client.run_shuffle_phase(&recvaddr).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("shuffling phase failed: {}", e),
        )
    }).unwrap();
    println!("final list is : {:?}", client.commitmsg.final_list.clone());
    client.verification_phase().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("verification phase failed: {}", e),
        )
    }).unwrap();
    println!("After verification: final list is : {:?}\n v: {:?}\n r: {:?}\n s: {:?}", 
            client.commitmsg.final_list.clone(),
            client.commitmsg.signatures_v.clone(),
            client.commitmsg.signatures_r.clone(),
            client.commitmsg.signatures_s.clone(),);
    for i in 0..client.peers.len() {
        println!("sender {}: {:?}",i, client.peers[i].acc);
    }
}
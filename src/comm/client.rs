//! # Client
//!
//! Defines the client operation for CoinShuffling

use super::errors;
use super::funccall::{transferfunc, lookup_balance_byaddr_and_check, lookup_ek_byaddr_and_check};
use super::messages::{Message, BlameReason, BlameShuffling};
use super::net::Connector;
use super::peers::{AccountNum, AccountNumEnc, Peer};
use ecies_ed25519 as ecies;
use rand::{self, seq::SliceRandom};
use sha3::{Digest, Keccak256};
use std::collections::HashSet;
use std::io;
//for contract call
use web3::types::U256;
use tokio2::runtime::Runtime;

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
    /// Creates a new `Client` from the underlying connection, other peer *ethereum addresses*,
    /// *self ethereum address*, and *own ethereum signing key*.
    pub fn new<'a, 'b: 'a>(
        conn: C,
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

        peers[my_id as usize].ek = ek;

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
                if id != prev_peer.id {
                    return Err(errors::unexpected_peer_id(id));
                }

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
                    return Err(errors::incorrect_session_number(session_id, derived_acc));
                }

                // the signer is not the one with the given id
                if *derived_acc != peer_acc {
                    return Err(errors::impersonalisation(derived_acc));
                }

                // verify the signature
                match vk.verify(&signature, msg_hash.as_slice()) {
                    Ok(valid) if !valid => {
                        return Err(errors::signature_invalid(derived_acc));
                    }
                    Err(e) => return Err(errors::could_not_verify_signature(e, derived_acc)),
                    _ => (),
                }
                perm
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "expected permutation message",
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

        // if I am not the last peer
        if (self.my_id as usize) < self.peers.len() - 1 {
            let next_peer = &self.peers[self.my_id as usize + 1];

            let mut hasher = Keccak256::new();

            permutation.iter().for_each(|x| hasher.update(x));
            hasher.update(&[2u8]);
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

            let m = Message::Permutation {
                id: self.my_id,
                perm: permutation,
                session_id: self.session_id,
                signature_v,
                signature_r,
                signature_s,
            };

            self.conn.send_to(&next_peer, m)?;
        } else {
            // TODO create and output transaction
        }

        Ok(())
    }

    pub fn trigger_blame_phase(&mut self, msg: BlameReason, shuffleinfo: Option<BlameShuffling>) -> io::Result<()> {
        if let BlameReason::NotEnoughBalance (adversary_id) = msg {
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
            println!("Peer address {:?} doesn't have enough balance in contract", self.peers[adversary_id as usize].acc);
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "The blame message is broadcasted. Quit now ...",
            ))      
        } else if let BlameReason::IncorrectKeyExchange (adversary_id) = msg {
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
            println!("Peer address {:?} doesn't send correct dnc key in contract", self.peers[adversary_id as usize].acc);
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "The blame message is broadcasted. Quit now ...",
            ))  
        } else if let BlameReason::IncorrectShuffling (adversary_id) = msg {
            if let BlameShuffling::BlameInformation {
                ad_id,
                ad_perm,
                ad_session_id,
                ad_signature_v,
                ad_signature_r,
                ad_signature_s,  
            } = shuffleinfo.unwrap()
            {
                let mut hasher = Keccak256::new();
                hasher.update(self.my_id.to_le_bytes());
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
                println!("Peer address {:?} sends incorrect Shuffle message", self.peers[adversary_id as usize].acc);
                Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "Incorrect Shuffle message from the previous peers. Dnc key is broadcasted. Quit now ...",
                ))   
            }else{
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected permutation message",
                ))                
            }
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
            }else if let BlameReason::IncorrectKeyExchange(adversary_id) = blame_msg {
                hasher.update(adversary_id.to_le_bytes());
            }else if let BlameReason::IncorrectShuffling(adversary_id) = blame_msg {
                hasher.update(adversary_id.to_le_bytes());
                if let BlameShuffling::BlameInformation {
                    ad_id: _,
                    ref ad_perm,
                    ad_session_id,
                    ad_signature_v,
                    ad_signature_r,
                    ad_signature_s,  
                } = peerincorrectshuffleinfo
                {
                    hasher.update(dk.unwrap());
                    ad_perm.iter().for_each(|x| hasher.update(x));
                    hasher.update(ad_session_id.to_le_bytes());
                    hasher.update(ad_signature_v.to_le_bytes());
                    hasher.update(ad_signature_r);
                    hasher.update(ad_signature_s);
                }
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
                )).unwrap();
            }else if let BlameReason::IncorrectKeyExchange(adversary_id) = blame_msg {
                let mut rt = Runtime::new().unwrap();
                rt.block_on(lookup_ek_byaddr_and_check(
                    self.contract_address, 
                    self.abi.clone(),
                    self.commiter,
                    self.peers[adversary_id as usize].acc,
                    U256::from(self.peers[adversary_id as usize].ek.to_bytes()),
                )).unwrap();
            }else if let BlameReason::IncorrectShuffling(adversary_id) = blame_msg {
                let peerincorrectshuffleinfo2 = peerincorrectshuffleinfo.clone();
                if let BlameShuffling::BlameInformation {
                    ad_id,
                    ad_perm,
                    ad_session_id,
                    ad_signature_v,
                    ad_signature_r,
                    ad_signature_s,  
                } = peerincorrectshuffleinfo2
                {
                    if ad_id as usize != id as usize - 1 {
                        println!("Peer address {:?} sends incorrect Shuffle message", self.peers[adversary_id as usize].acc);
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
    
                    ad_perm.iter().for_each(|b| hasher.update(b));
                    hasher.update(&[2u8]);
                    hasher.update(ad_session_id.to_le_bytes());
    
                    let msg_hash = hasher.finalize();
    
                    // FIXME Repetitive code
                    let vk = self.recover_pub_key(&msg_hash, &signature)?;
    
                    let derived_acc = vk.address();
                    let peer_acc = self.peers[id as usize].acc;
    
                    // check the session id
                    if session_id != ad_session_id {
                        println!("Peer address {:?} sends incorrect Shuffle message", self.peers[adversary_id as usize].acc);
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "Incorrect Shuffle message from the previous peers. Quit now ...",
                        ));
                    }
    
                    // the signer is not the one with the given id
                    if *derived_acc != peer_acc {
                        println!("Peer address {:?} sends incorrect Shuffle message", self.peers[adversary_id as usize].acc);
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "Incorrect Shuffle message from the previous peers. Quit now ...",
                        ));
                    }
    
                    // verify the signature
                    match vk.verify(&signature, msg_hash.as_slice()) {
                        Ok(valid) if !valid => {
                            println!("Peer address {:?} sends incorrect Shuffle message", self.peers[adversary_id as usize].acc);
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "Incorrect Shuffle message from the previous peers. Quit now ...",
                            ));
                        }
                        Err(_) => {
                            println!("Peer address {:?} sends incorrect Shuffle message", self.peers[adversary_id as usize].acc);
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "Incorrect Shuffle message from the previous peers. Quit now ...",
                            ));
                        }
                        _ => (),
                    }                    
                }
            }
            Ok(())
        }else{
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected blame message",
            ))           
        }
    }

    pub fn verification_phase(&mut self) -> io::Result<()> {
        Ok(())
    }

    pub fn run_commit_phase(
        &mut self, 
        commiter: AccountNum, 
        contract_address: AccountNum, 
        abi: String,
    ) -> io::Result<()> {
        self.commitmsg.signatures_v = vec![0_u8;self.peers.len()];
        self.commitmsg.signatures_r = vec![[0_u8;32];self.peers.len()];
        self.commitmsg.signatures_s = vec![[0_u8;32];self.peers.len()];
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
                self.peers[id as usize].ek = ek;
            }
        }

        Ok(())
    }
    fn sign_announce_commitmsg(&mut self) -> io::Result<()> {
        let mut hasher = Keccak256::new();
        let senders: Vec<AccountNum> = self.peers.iter().map(|p| p.acc).collect();
        let receivers = self.commitmsg.final_list.clone();
        let no_of_claimers = self.peers.len() as u16;
        hasher.update(self.my_id.to_le_bytes());
        for i in &senders {
            hasher.update(i);
        }
        for i in &receivers {
            hasher.update(i);
        }
        hasher.update(no_of_claimers.to_le_bytes());
        hasher.update(self.amount.to_le_bytes());
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
        while valid_insert_times < n {
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

                let signature = ethkey::Signature {
                    r: signature_r,
                    s: signature_s,
                    v: signature_v,
                };

                let mut hasher = Keccak256::new();

                hasher.update(id.to_le_bytes());
                for i in &senders {
                    hasher.update(i);
                }
                for i in &receivers {
                    hasher.update(i);
                }
                hasher.update(no_of_claimers.to_le_bytes());
                hasher.update(amount.to_le_bytes());

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
            }
        }

        Ok(())
    }

    fn commit(&mut self, commiter: AccountNum, contract_address: AccountNum, abi: String,) -> io::Result<()> {
        assert_ne!(self.peers[self.my_id as usize].acc, commiter, 
            "You're not the correct account number to commit the block!");
        let senders: Vec<[u8;20]> = self.peers.iter().map(|i| i.acc).collect();
        let receivers: Vec<[u8;20]> = self.commitmsg.final_list.clone();
        let noofclaimers = self.commitmsg.final_list.len() as u128;
        let amount = U256::from(self.amount);
        let v: Vec<u8> = self.commitmsg.signatures_v.clone();
        let r: Vec<U256> = self.commitmsg.signatures_r.clone().iter().map(|i| U256::from(i)).collect();
        let s: Vec<U256> = self.commitmsg.signatures_s.clone().iter().map(|i| U256::from(i)).collect();
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
        )).unwrap();
        Ok(())
    }
}

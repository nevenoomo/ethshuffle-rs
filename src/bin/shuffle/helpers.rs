use ethshuffle_rs::peers::AccountNum;
use ethsign::SecretKey;
use rand::prelude::*;
use rand_chacha::ChaCha8Rng;
use rustc_hex::FromHex;
use std::convert::TryInto;
use std::io;

pub fn parse_eth_addr(s: &str) -> io::Result<AccountNum> {
    if s.len() != 42 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("number of bytes in account is invalid: {}, expected input format: 0x????????????????????", s),
        ));
    }

    let s = &s[2..];

    let res_vec: Vec<u8> = s.from_hex().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "failed to parse account address: {}, due to error: {}",
                s, e
            ),
        )
    })?;

    let res = res_vec.try_into().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "number of bytes in account is invalid: {}, due to error: {:?}",
                s, e
            ),
        )
    })?;

    Ok(res)
}

pub fn parse_secret_key(s: &str) -> io::Result<SecretKey> {
    if s.len() != 66 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("number of bytes in secret key is invalid: {}, expected input format: 0x????????????????????", s),
        ));
    }
    
    let s = &s[2..];    

    let res_vec: Vec<u8> = s.from_hex().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to parse the secret key due to error: {}", e),
        )
    })?;

    SecretKey::from_raw(&res_vec).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("failed to parse the secret key due to error: {}", e),
        )
    })
}

pub fn choose_commiter(accs: &[AccountNum], seed: u64) -> &AccountNum {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    let commiter_idx: usize = rng.gen_range(0, accs.len());

    &accs[commiter_idx]
}

pub fn get_client_account(accs: &[AccountNum]) -> io::Result<&AccountNum> {
    if accs.len() == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "no accounts specified",
        ));
    }

    Ok(&accs[0])
}

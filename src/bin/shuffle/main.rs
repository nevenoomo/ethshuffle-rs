use ethkey::{EthAccount, Password, SecretKey};
use ethshuffle_rs::{client::Client, net::RelayConnector, peers::AccountNum};
use std::convert::TryInto;
use std::fmt::Debug;
use std::io;
use std::net::{ToSocketAddrs};
use std::path::Path;
use clap::ArgMatches;

mod ui;
mod helpers;

fn run<S: ToSocketAddrs, P: AsRef<Path> + Debug>(
    addr: S,
    session_id: u64,
    peer_accounts: Vec<AccountNum>,
    this_account: AccountNum,
    sk: SecretKey,
    commiter: AccountNum,
    contract_address: AccountNum,
    abi: String,
    amount: u32,
    output_passwd: Password,
    output_path: P,
) -> io::Result<()> {
    let conn = RelayConnector::new(addr)?;
    let mut client = Client::new(
        conn,
        session_id,
        peer_accounts.iter().collect(),
        &this_account,
        sk,
        commiter,
        contract_address,
        abi,
        amount,
    );

    client.run_announcement_phase()?;

    let acc = EthAccount::load_or_generate(output_path.as_ref(), output_passwd).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "could not use keystore {:?} as and output: {}",
                output_path, e
            ),
        )
    })?;

    let addr: AccountNum = acc.address().to_vec().try_into().unwrap();
    client.run_shuffle_phase(&addr).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("shuffling phase failed: {}", e),
        )
    })?;
    client.verification_phase().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("verification phase failed: {}", e),
        )
    })?;

    Ok(())
}

fn run_tui() -> io::Result<()> {
    unimplemented!("TUI is not yet supported");
}

fn run_cli(matches: ArgMatches) -> io::Result<()> {
    unimplemented!("CLI is not yet supported");
} 

fn main() {
    let matches = ui::parse_cli_args();

    let result = if matches.is_present("tui") {
        run_tui()
    } else {
        run_cli(matches)
    };

    if let Err(e) = result {
        eprintln!("Failed to perform shuffling due to error: {}", e);
    }
}

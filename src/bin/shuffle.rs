use clap::{App, Arg};
use ethkey::{EthAccount, Password, SecretKey};
use ethshuffle_rs::{client::Client, net::RelayConnector, peers::AccountNum, DEFAULT_PORT};
use std::convert::TryInto;
use std::fmt::Debug;
use std::io;
use std::net::{IpAddr, ToSocketAddrs};
use std::path::Path;
use std::str::FromStr;

fn run<S: ToSocketAddrs, P: AsRef<Path> + Debug>(
    addr: S,
    session_id: u64,
    peer_accounts: Vec<&AccountNum>,
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
        peer_accounts,
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

fn main() {
    let matches = App::new("EthShuffle - Ethereum Coin Mixing")
        .version(env!("CARGO_PKG_VERSION"))
        // MAYBE add about
        .arg(
            Arg::with_name("addr")
                .help("relay server address")
                .long("addr")
                .short("a")
                .takes_value(true)
                .value_name("IP_ADDR")
                .required(false)
                .default_value("0.0.0.0")
                .validator(|x| match IpAddr::from_str(x.as_str()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("incorrect IP address")),
                }),
        )
        .arg(
            Arg::with_name("port")
                .help("relay server port")
                .long("port")
                .short("p")
                .required(false)
                .takes_value(true)
                .value_name("PORT")
                .default_value(DEFAULT_PORT)
                .validator(|x| match x.parse::<u16>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Incorrect port")),
                }),
        )
        .arg(
            // FIXME omit this parameter and make implementation work with any number of participants
            Arg::with_name("#participants")
                .help("the number of participants in the shuffling protocols")
                .long("participants")
                .short("n")
                .required(true)
                .takes_value(true)
                .value_name("#PARTICIPANTS")
                .validator(|x| match x.parse::<u16>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Incorrect number of participants")),
                }),
        )
        .arg(
            Arg::with_name("peer_accounts")
                .help("file with the list of Ethereum account addresses of other protocol participants")
                .long("accounts")
                .short("a")
                .required(true)
                .takes_value(true)
                .value_name("ACCOUNTS_FILE")
        )
        .arg(
            Arg::with_name("keystore")
                .help("keystore of the clients Ethereum account; includes account's private and public keys")
                .long("keystore")
                .short("k")
                .required(true)
                .takes_value(true)
                .value_name("KEYSTORE_FILE")
        )
        .arg(
            Arg::with_name("amount")
                .help("amount of Ether to be shuffled")
                .long("amount")
                .short("a")
                .required(true)
                .takes_value(true)
                .value_name("AMOUNT")
        )
        .arg(
            Arg::with_name("session_id")
                .help("session ID of the performed shuffling; should be agreed upon by all peers")
                .long("session-id")
                .short("s")
                .required(true)
                .takes_value(true)
                .value_name("SESSION_ID")
        )
        .get_matches();
}

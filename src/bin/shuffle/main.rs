use clap::ArgMatches;
use ethkey::EthAccount;
use ethshuffle_rs::{client::Client, net::RelayConnector, peers::AccountNum};
use ethsign::SecretKey;
use std::convert::TryInto;
use std::fs::{read_to_string, File};
use std::io::{self, BufRead};
use std::net::IpAddr;
use std::net::ToSocketAddrs;
use std::path::Path;
use std::str::FromStr;
use std::string::ToString;

mod helpers;
mod ui;

fn run<S: ToSocketAddrs>(
    addr: S,
    session_id: u64,
    peer_accounts: Vec<AccountNum>,
    this_account: AccountNum,
    sk: SecretKey,
    commiter: AccountNum,
    contract_address: AccountNum,
    abi: String,
    amount: u32,
    output_account: AccountNum,
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

    client.run_shuffle_phase(&output_account).map_err(|e| {
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
    let addr = IpAddr::from_str(matches.value_of("addr").unwrap()).unwrap();
    let port = matches.value_of("port").unwrap().parse::<u16>().unwrap();
    let socket_addr = (addr, port);
    let accounts_filename = matches.value_of("accounts").unwrap();

    let accounts_file = File::open(accounts_filename).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "could not open file with peer accounts {}: {}",
                accounts_filename, e
            ),
        )
    })?;
    let accounts_reader = io::BufReader::new(accounts_file);

    let mut accounts = accounts_reader
        .lines()
        .map(|l| helpers::parse_eth_addr(&l.unwrap()))
        .collect::<io::Result<Vec<AccountNum>>>()?;

    let this_account = helpers::get_client_account(&accounts)?.clone();
    accounts.sort();
    let keystore_filename = matches.value_of("keystore").unwrap();
    let keystore_file = File::open(keystore_filename).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "could not open the specified keystore {}: {}",
                keystore_filename, e
            ),
        )
    })?;
    let keystore_pass: ethsign::Protected = matches.value_of("keystore_pass").unwrap().into();
    let keystore: ethsign::KeyFile = serde_json::from_reader(keystore_file).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("keystore {} format is incorrect: {}", keystore_filename, e),
        )
    })?;
    let sk = keystore.to_secret_key(&keystore_pass).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "could not get the secret key from specified keystore {}: {}",
                keystore_filename, e
            ),
        )
    })?;
    let amount = matches.value_of("amount").unwrap().parse::<u32>().unwrap();
    let session_id = matches
        .value_of("session_id")
        .unwrap()
        .parse::<u64>()
        .unwrap();

    // let commiter = helpers::choose_commiter(&accounts, session_id).clone();
    let commiter =
        helpers::parse_eth_addr(matches.value_of("commiter_addr").unwrap()).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("the commiter address is invalid: {}", e),
            )
        })?;

    let abi = matches.value_of("abi").unwrap().to_string();

    if !Path::new(&abi).exists() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("could not read the specified ABI file"),
        ));
    }

    let contract_addr = helpers::parse_eth_addr(&matches.value_of("contract_addr").unwrap())?;
    let output_path = matches.value_of("output_path").unwrap();

    let ouput_addr: AccountNum = if Path::new(output_path).exists() {
        let output_file = File::open(output_path)?;
        let output: ethsign::KeyFile = serde_json::from_reader(output_file).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("output keystore {} format is incorrect: {}", output_path, e),
            )
        })?;

        match output.address {
            Some(addr) => addr.0.try_into().unwrap(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "no account address in specified output keystore {}",
                        output_path
                    ),
                ))
            }
        }
    } else {
        let password = loop {
            let res = dialoguer::Password::new()
                .allow_empty_password(true)
                .with_prompt("Type in password for the new keystore")
                .with_confirmation("Confirm password", "Sorry, passwords do not match...")
                .interact();

            if let Err(e) = res {
                eprintln!("{}", e);
                println!("Please, try again");
            } else {
                break res.unwrap();
            }
        };

        let acc = EthAccount::load_or_generate(output_path, password).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("could not use keystore {} as an output: {}", output_path, e),
            )
        })?;

        acc.address().to_vec().try_into().unwrap()
    };

    run(
        socket_addr,
        session_id,
        accounts,
        this_account,
        sk,
        commiter,
        contract_addr,
        abi.to_string(),
        amount,
        ouput_addr,
    )
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

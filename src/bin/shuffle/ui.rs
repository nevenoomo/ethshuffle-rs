use clap::{App, Arg, ArgMatches};
use ethshuffle_rs::DEFAULT_PORT;
use std::net::IpAddr;
use std::str::FromStr;

pub fn parse_cli_args<'a>() -> ArgMatches<'a> {
    App::new("EthShuffle - Ethereum Coin Mixing")
        .version(env!("CARGO_PKG_VERSION"))
        // MAYBE add about
        .arg_from_usage("[tui] --tui 'Run the Terminal UI session. Other would be ignored.'")
        .arg(
            Arg::with_name("addr")
                .display_order(1)
                .help("Relay server address.")
                .long("addr")
                .short("a")
                .takes_value(true)
                .value_name("IP_ADDR")
                .default_value("0.0.0.0")
                .validator(|x| match IpAddr::from_str(x.as_str()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("incorrect IP address")),
                }),
        )
        .arg(
            Arg::with_name("port")
                .display_order(2)
                .help("relay server port")
                .long("port")
                .short("p")
                .takes_value(true)
                .value_name("PORT")
                .default_value(DEFAULT_PORT)
                .validator(|x| match x.parse::<u16>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("incorrect port")),
                }),
        )
        .arg(
            Arg::with_name("session_id")
                .display_order(3)
                .help("Session ID of the performed shuffling. Should be agreed upon by all peers.")
                .long("session-id")
                .short("s")
                .required_unless("tui")
                .takes_value(true)
                .value_name("SESSION_ID")
                .validator(|x| match x.parse::<u64>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("invalid session ID")),
                }),
        )
        .arg(
            Arg::with_name("amount")
                .display_order(4)
                .help("Amount of Ether to be shuffled.")
                .long("amount")
                .short("n")
                .required_unless("tui")
                .takes_value(true)
                .value_name("AMOUNT")
                .validator(|x| match x.parse::<u32>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("invalid amount")),
                }),
        )
        .arg(
            Arg::with_name("accounts")
                .display_order(5)
                .help("File with the list of Ethereum account addresses of all protocol participants. YOUR ADDRESS MUST BE THE FIRST ONE.")
                .long("accounts")
                .short("l")
                .required_unless("tui")
                .takes_value(true)
                .value_name("ACCOUNTS_FILE")
        )
        .arg(
            // TODO Default to our contract address
            Arg::with_name("contract_addr")
                .display_order(6)
                .help("Address of the Ethereum contract to be used during shuffling.")
                .long("contract_addr")
                .short("c")
                .required_unless("tui")
                .takes_value(true)
                .value_name("CONTRACT_ADDR")
        )
        .arg(
            Arg::with_name("keystore")
                .display_order(7)
                .help("Keystore of the clients Ethereum account. Includes account's private and public keys")
                .long("keystore")
                .short("k")
                .required_unless("tui")
                .takes_value(true)
                .value_name("KEYSTORE_FILE")
        )
        .arg(
            Arg::with_name("keystore_pass")
                .display_order(8)
                .help("Keystore password.")
                .long("keystore_pass")
                .short("r")
                .required_unless("tui")
                .takes_value(true)
                .value_name("KEYSTORE_PASS")
        )
        .arg(
            Arg::with_name("output_path")
                .display_order(9)
                .help("Path to the keystore of the output. If file exists, will output to the address in it, otherwise will generate a new keystore.")
                .short("o")
                .long("output-path")
                .takes_value(true)
                .value_name("PATH_TO_OUTPUT")
                .default_value("./output_account.json")
                .hide_default_value(true)
        )
        .arg(
            Arg::with_name("abi")
                .display_order(10)
                .help("Path to custom contract abi to be used.")
                .long("abi")
                .takes_value(true)
                .value_name("PATH_TO_ABI")
        )
        .arg(
            // FIXME remove
            Arg::with_name("commiter_addr")
                .display_order(9)
                .help("Ethereum address of the one peer supposed to commit the final transaction.")
                .long("commiter")
                .takes_value(true)
                .required_unless("TUI")
                .value_name("COMMITER_ADDR")
        )
        .get_matches()
}

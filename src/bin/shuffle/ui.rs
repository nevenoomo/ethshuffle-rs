use clap::{App, Arg, ArgMatches};
use ethshuffle_rs::DEFAULT_PORT;
use std::net::IpAddr;
use std::str::FromStr;

pub fn parse_cli_args<'a>() -> ArgMatches<'a> {
    App::new("EthShuffle - Ethereum Coin Mixing")
        .version(env!("CARGO_PKG_VERSION"))
        // MAYBE add about
        .arg_from_usage("[tui] --tui 'run the Terminal UI session. Other would be ignored.'")
        .arg(
            Arg::with_name("addr")
                .help("relay server address")
                .long("addr")
                .short("a")
                .takes_value(true)
                .value_name("IP_ADDR")
                .required_unless("tui")
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
                .required_unless("tui")
                .takes_value(true)
                .value_name("PORT")
                .default_value(DEFAULT_PORT)
                .validator(|x| match x.parse::<u16>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Incorrect port")),
                }),
        )
        .arg(
            Arg::with_name("peer_accounts")
                .help("file with the list of Ethereum account addresses of other protocol participants")
                .long("accounts")
                .short("a")
                .required_unless("tui")
                .takes_value(true)
                .value_name("ACCOUNTS_FILE")
        )
        .arg(
            Arg::with_name("keystore")
                .help("keystore of the clients Ethereum account; includes account's private and public keys")
                .long("keystore")
                .short("k")
                .required_unless("tui")
                .takes_value(true)
                .value_name("KEYSTORE_FILE")
        )
        .arg(
            Arg::with_name("amount")
                .help("amount of Ether to be shuffled")
                .long("amount")
                .short("a")
                .required_unless("tui")
                .takes_value(true)
                .value_name("AMOUNT")
        )
        .arg(
            Arg::with_name("session_id")
                .help("session ID of the performed shuffling; should be agreed upon by all peers")
                .long("session-id")
                .short("s")
                .required_unless("tui")
                .takes_value(true)
                .value_name("SESSION_ID")
        ).get_matches()
}

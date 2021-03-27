use tokio2::runtime::Runtime;
use std::error::Error;
use clap::{App, Arg};
use std::path::Path;
use ethshuffle_rs::funccall::follow_register;
use hex::FromHex;
use web3::types::U256;
fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("EthShuffle Contract Register")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Register EthShuffle contract")
        .arg(
            Arg::with_name("abi")
                .help("contract abi-json")
                .long("abi")
                .short("a")
                .takes_value(true)
                .value_name("ABI")
                .required(true)
                .validator(|x| match Path::new(x.as_str()).exists(){
                    true => Ok(()),
                    _ => Err(String::from("Abi-json file not exist")),
                }),
        )
        .arg(
            Arg::with_name("acc")
                .help("account address")
                .long("account")
                .short("acc")
                .takes_value(true)
                .value_name("ACC")
                .required(true),
        )
        .arg(
            Arg::with_name("cont")
                .help("contract address")
                .long("contract")
                .short("cont")
                .takes_value(true)
                .value_name("CONT")
                .required(true),
        )
        .arg(
            Arg::with_name("first_claimer")
                .help("first claimer account address")
                .long("firstclaimer")
                .short("f")
                .takes_value(true)
                .value_name("FIRSTCLAIMER")
                .required(true),
        )
        .arg(
            Arg::with_name("amount")
                .help("amount to be transferred")
                .long("amount")
                .short("a")
                .required(true)
                .takes_value(true)
                .value_name("AMOUNT")
                .validator(|x| match x.parse::<u32>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Incorrect Amount Format")),
                }),
        )
        .get_matches();
    let abi = matches.value_of("abi").unwrap();
    let accstring = matches.value_of("acc").unwrap();
    let account: [u8; 20] = <[u8; 20]>::from_hex(accstring).expect("Decoding failed");

    let contstring = matches.value_of("cont").unwrap();
    let contaddr: [u8; 20] = <[u8; 20]>::from_hex(contstring).expect("Decoding failed");

    let firstaccstring = matches.value_of("first_claimer").unwrap();
    let firstaccount: [u8; 20] = <[u8; 20]>::from_hex(firstaccstring).expect("Decoding failed");    

    let amount = matches.value_of("amount").unwrap().parse::<u32>().unwrap();
    let amount_deposit: U256 = U256::from(amount);
    let mut rt = Runtime::new().unwrap();

    rt.block_on(follow_register(
        account,
        contaddr,
        abi.to_string(),
        firstaccount,
        amount_deposit,
    )).unwrap();
    Ok(())
}
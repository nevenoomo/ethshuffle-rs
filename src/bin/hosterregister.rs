use tokio2::runtime::Runtime;
use std::error::Error;
use clap::{App, Arg};
use std::path::Path;
use ethshuffle_rs::funccall::init_register;
use hex::FromHex;
use ethshuffle_rs::DEFAULT_PORT;
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
            Arg::with_name("addr")
                .help("relay server address")
                .long("addr")
                .short("a")
                .takes_value(true)
                .value_name("IP_ADDR")
                .required(false)
                .default_value("0.0.0.0")
                .validator(|x| match x.parse::<u32>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("incorrect IP address")),
                }),
        )
        .arg(
            Arg::with_name("port")
                .help("relay server port")
                .long("port")
                .short("p")
                .required(true)
                .takes_value(true)
                .value_name("PORT")
                .default_value(DEFAULT_PORT)
                .validator(|x| match x.parse::<u16>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Incorrect port")),
                }),
        )
        .arg(
            Arg::with_name("register_deadline")
                .help("register deadline")
                .long("register_deadline")
                .short("r")
                .required(true)
                .takes_value(true)
                .value_name("REG")
                .validator(|x| match x.parse::<u128>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Incorrect Timestamp")),
                }),
        )
        .arg(
            Arg::with_name("hoster_start_timestamp")
                .help("hoster start timestamp")
                .long("hoster_start_timestamp")
                .short("s")
                .required(true)
                .takes_value(true)
                .value_name("STARTTIME")
                .validator(|x| match x.parse::<u128>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Incorrect Timestamp")),
                }),
        )
        .arg(
            Arg::with_name("hoster_end_timestamp")
                .help("hoster end timestamp")
                .long("hoster_end_timestamp")
                .short("s")
                .required(true)
                .takes_value(true)
                .value_name("ENDTIME")
                .validator(|x| match x.parse::<u128>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Incorrect Timestamp")),
                }),
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

    let ipaddr = matches.value_of("addr").unwrap().parse::<u32>().unwrap();
    let port = matches.value_of("port").unwrap().parse::<u16>().unwrap();
    let amount = matches.value_of("amount").unwrap().parse::<u32>().unwrap();
    let register_deadline = matches.value_of("register_deadline").unwrap().parse::<u128>().unwrap();
    let hoster_start_timestamp = matches.value_of("hoster_start_timestamp").unwrap().parse::<u128>().unwrap();
    let hoster_end_timestamp = matches.value_of("hoster_end_timestamp").unwrap().parse::<u128>().unwrap();
    let amount_deposit: U256 = U256::from(amount);
    let mut rt = Runtime::new().unwrap();

    rt.block_on(init_register(
        account,
        contaddr,
        abi.to_string(),
        register_deadline,
        hoster_start_timestamp,
        hoster_end_timestamp,
        ipaddr,
        port,
        amount_deposit,
    )).unwrap();
    Ok(())
}
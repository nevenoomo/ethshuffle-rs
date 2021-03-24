use web3::{
    contract::{Contract, Options},
    types::Address,
};
use std::fs;
use tokio2::runtime::Runtime;
use std::error::Error;
use clap::{App, Arg};
use std::path::Path;
use std::time;

async fn devdeploy(bin: String, abi: String) -> web3::contract::Result<()> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    // Get current balance
    let raw_account = [0x77,0x40,0x62,0x7c,0x47,0x1d,0x18,0x44,0x01,0xa1,0x17,0xcd,0xA2,0xAf,0x5c,0x20,0xb2,0x14,0x15,0xC9];
    let account = Address::from_slice(&raw_account);
    let balance = web3.eth().balance(account, None).await?;
    println!("Balance: {}", balance);

    // Get the contract bytecode for instance from Solidity compiler
    let bytecode = fs::read_to_string(bin).unwrap();
    let abicontentstr = fs::read_to_string(abi).unwrap();
    let abicontent = abicontentstr.as_bytes();
    // Deploying a contract
    let contract = Contract::deploy(web3.eth(), abicontent)?
        .confirmations(1)
        .poll_interval(time::Duration::from_secs(10))
        .options(Options::with(|opt| opt.gas = Some(3_000_000.into())))
        .execute(bytecode, (), account)
        .await?;
    println!("Deployed at: {:?}", contract.address().as_bytes());
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("EthShuffle Contract Deployment")
        .version(env!("CARGO_PKG_VERSION"))
        .about("It is not suggested for clients to deploy EthShuffle contract")
        .arg(
            Arg::with_name("bin")
                .help("contract bytecode")
                .long("bin")
                .short("b")
                .takes_value(true)
                .value_name("BIN")
                .required(true)
                .validator(|x| match Path::new(x.as_str()).exists(){
                    true => Ok(()),
                    _ => Err(String::from("Bin file not exist")),
                }),
        )
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
        .get_matches();

    let bin = matches.value_of("bin").unwrap();
    let abi = matches.value_of("abi").unwrap();

    let mut rt = Runtime::new().unwrap();
    rt.block_on(devdeploy(bin.to_string(), abi.to_string()))?;
    Ok(())
}

#[test]
fn deploy_test() {
    let mut rt = Runtime::new().unwrap();
    rt.block_on(devdeploy(
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.bin".to_string(),
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
    )).unwrap();  
}
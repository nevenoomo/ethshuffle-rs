use web3::{
    contract::{Contract, Options},
    types::U256,
    types::Address,
};
use ethabi;
use std::fs::File;
use tokio2::runtime::Runtime;
use std::error::Error;

async fn funccall() -> web3::contract::Result<()> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    let accounts = web3.eth().accounts().await?;

    // Get current balance
    let balance = web3.eth().balance(accounts[0], None).await?;

    println!("Balance: {}", balance);

    // Get the contract bytecode for instance from Solidity compiler
    // let bytecode = include_str!("/Users/zandent/Files/csc2125/ethshuffle-rs/res/SimpleStorage.bin");
    // Deploying a contract
    // let contract = Contract::deploy(web3.eth(), include_bytes!("./res/SimpleStorage.abi"))?
    //     .confirmations(1)
    //     .poll_interval(time::Duration::from_secs(10))
    //     .options(Options::with(|opt| opt.gas = Some(3_000_000.into())))
    //     .execute(bytecode, (), accounts[0])
    //     .await?;
    let json = File::open("/Users/zandent/Files/csc2125/ethshuffle-rs/res/SimpleStorage.abi").unwrap();
    let abi = ethabi::Contract::load(json).unwrap();
    let raw_address = [0xee,0x32,0xf5,0xd3,0x18,0xb7,0x9b,0x4d,0x77,0x9d,0xdb,0x7b,0xfb,0x45,0x76,0x91,0xf9,0x12,0xbb,0xf6];
    let contract_address = Address::from_slice(&raw_address);
    let contract = Contract::new(web3.eth(), contract_address, abi);
    println!("Deployed at: {:?}", contract.address());

    // interact with the contract
    let result = contract.query("get", (), None, Options::default(), None);
    let storage: U256 = result.await?;
    println!("Get Storage: {:?}", storage);

    // Change state of the contract
    let tx = contract.call("set", (30_u32,), accounts[0], Options::default()).await?;
    println!("TxHash: {:?}", tx);

    // consider using `async_std::task::sleep` instead.
    std::thread::sleep(std::time::Duration::from_secs(5));

    // View changes made
    let result = contract.query("get", (), None, Options::default(), None);
    let storage: U256 = result.await?;
    println!("Get again: {:?}", storage);

    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let mut rt = Runtime::new().unwrap();
    rt.block_on(funccall())?;
    Ok(())
}
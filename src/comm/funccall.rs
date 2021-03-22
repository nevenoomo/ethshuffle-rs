use web3::{
    contract::{Contract, Options},
    types::Address,
};
use ethabi;
use std::fs::File;

async fn funccall(raw_account: [u8; 20], raw_contract_address: [u8; 20], abi: String) -> web3::contract::Result<()> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);

    // Get current balance
    let account = Address::from_slice(&raw_account);
    let balance = web3.eth().balance(account, None).await?;
    println!("Balance: {}", balance);

    let json = File::open(abi).unwrap();
    let abi = ethabi::Contract::load(json).unwrap();
    let contract_address = Address::from_slice(&raw_contract_address);
    let contract = Contract::new(web3.eth(), contract_address, abi);
    println!("Deployed at: {:?}", contract.address());

    // Change state of the contract
    let tx = contract.call_with_confirmations(
        "initRegister", 
        (   1,
            2,
            3,
            1,
            [1,2,3,4],
            0,
            1,
            [5,6,7,8],
        ),
        account, 
        Options::with(
            |opt| opt.value = Some(1000.into())
        ), 
        1)
        .await?;
    println!("TxHash: {:?}", tx);

    Ok(())
}

#[test]
fn init_register_test() {
    use tokio2::runtime::Runtime;
    let mut rt = Runtime::new().unwrap();
    rt.block_on(funccall(
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09], 
        [167, 26, 213, 146, 75, 54, 115, 4, 174, 246, 67, 66, 218, 248, 122, 50, 58, 103, 158, 244],
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
    )).unwrap();
}
use web3::{
    contract::{Contract, Options},
    types::{Address,U256},
};
use ethabi;
use std::fs::File;

async fn init_register(
    raw_account: [u8; 20], 
    raw_contract_address: [u8; 20], 
    abi: String,
    register_deadline: u128,
    hoster_start_timestamp: u128,
    hoster_end_timestamp: u128,
    hoster_ip_addr: u32,
    pubkey: U256,
    claimer_ip_addr: u32,
    amount_deposit: U256
) -> web3::contract::Result<()> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    // Get current balance
    let account = Address::from_slice(&raw_account);
    let balance = web3.eth().balance(account, None).await?;
    println!("Balance: {}", balance);
    let json = File::open(abi).unwrap();
    let abi_json = ethabi::Contract::load(json).unwrap();
    let contract_address = Address::from_slice(&raw_contract_address);
    let contract = Contract::new(web3.eth(), contract_address, abi_json);
    println!("Deployed at: {:?}", contract.address());
    let mut lo_pubkey = 0_u128;
    let mut hi_pubkey = 0_u128;
    for x in (0..16).rev() {
        lo_pubkey = lo_pubkey << 8 | u128::from(pubkey.byte(x));
        hi_pubkey = hi_pubkey << 8 | u128::from(pubkey.byte(x+16));
    }
    println!("msg.value is: {:#x}", amount_deposit);
    // Change state of the contract
    let tx = contract.call_with_confirmations(
        "initRegister", 
        (   register_deadline,
            hoster_start_timestamp,
            hoster_end_timestamp,
            true,
            hoster_ip_addr,
            lo_pubkey,
            hi_pubkey,
            true,
            claimer_ip_addr,
        ),
        account, 
        Options::with(
            |opt| {opt.value = Some(amount_deposit.into()); opt.gas = Some(3_000_000.into());}
        ), 
        1)
        .await?;
    println!("TxHash: {:?}", tx);
    Ok(())
}

async fn follow_register(
    raw_account: [u8; 20], 
    raw_contract_address: [u8; 20], 
    abi: String,
    raw_first_claimer: [u8; 20],
    pubkey: U256,
    claimer_ip_addr: u32,
    amount_deposit: U256
) -> web3::contract::Result<()> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    // Get current balance
    let account = Address::from_slice(&raw_account);
    let balance = web3.eth().balance(account, None).await?;
    println!("Balance: {}", balance);
    let json = File::open(abi).unwrap();
    let abi_json = ethabi::Contract::load(json).unwrap();
    let contract_address = Address::from_slice(&raw_contract_address);
    let contract = Contract::new(web3.eth(), contract_address, abi_json);
    println!("Deployed at: {:?}", contract.address());
    let mut lo_pubkey = 0_u128;
    let mut hi_pubkey = 0_u128;
    for x in (0..16).rev() {
        lo_pubkey = lo_pubkey << 8 | u128::from(pubkey.byte(x));
        hi_pubkey = hi_pubkey << 8 | u128::from(pubkey.byte(x+16));
    }
    let first_claimer = Address::from_slice(&raw_first_claimer);
    println!("msg.value is: {:#x}", amount_deposit);
    // Change state of the contract
    let tx = contract.call_with_confirmations(
        "followRegister", 
        (   first_claimer,
            lo_pubkey,
            hi_pubkey,
            true,
            claimer_ip_addr,
        ),
        account, 
        Options::with(
            |opt| {opt.value = Some(amount_deposit.into()); opt.gas = Some(3_000_000.into());}
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
    let predefined_contract_address = [238, 50, 245, 211, 24, 183, 155, 77, 119, 157, 219, 123, 251, 69, 118, 145, 249, 18, 187, 246];
    rt.block_on(init_register(
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09], 
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        1716449919_u128,
        1816449919_u128,
        1916449919_u128,
        0x7F000002_u32,
        U256([0xDE_u64,0xAD_u64,0xBE_u64,0xEF_u64]),
        0x7F000003_u32,
        U256([0x0F_u64,0x00_u64,0x00_u64,0x00_u64]),
    )).unwrap();
    rt.block_on(follow_register(
        [0x44,0xde,0x1f,0xaA,0xa2,0xFc,0x62,0x27,0x05,0x00,0xBe,0xA1,0xde,0x45,0x71,0x6f,0xf3,0x2F,0xc9,0x45], 
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
        U256([0xDE_u64,0xAD_u64,0xBE_u64,0xEF_u64]),
        0x7F000003_u32,
        U256([0x0F_u64,0x00_u64,0x00_u64,0x00_u64]),
    )).unwrap();
}
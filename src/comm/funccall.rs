use web3::{
    contract::{Contract, Options},
    types::{Address,U256},
};
use web3::contract::Error::InvalidOutputType;
use ethabi;
use ethabi::Token;
use std::fs::File;
use web3::contract::tokens::Tokenizable;
use std::fs;
use std::time;

pub async fn devdeploy(raw_account: [u8; 20], bin: String, abi: String) -> web3::contract::Result<()> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    // Get current balance
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
        .options(Options::with(|opt| opt.gas = Some(5_000_000.into())))
        .execute(bytecode, (), account)
        .await?;
    println!("Deployed at: {:?}", contract.address().as_bytes());
    Ok(())
}

pub async fn init_register(
    raw_account: [u8; 20], 
    raw_contract_address: [u8; 20], 
    abi: String,
    register_deadline: u128,
    hoster_start_timestamp: u128,
    hoster_end_timestamp: u128,
    hoster_ip_addr: u32,
    port: u16,
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
    println!("msg.value is: {:#x}", amount_deposit);
    // Change state of the contract
    let tx = contract.call_with_confirmations(
        "initRegister", 
        (   register_deadline,
            hoster_start_timestamp,
            hoster_end_timestamp,
            hoster_ip_addr,
            port,
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

pub async fn follow_register(
    raw_account: [u8; 20], 
    raw_contract_address: [u8; 20], 
    abi: String,
    raw_first_claimer: [u8; 20],
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
    let first_claimer = Address::from_slice(&raw_first_claimer);
    println!("msg.value is: {:#x}", amount_deposit);
    // Change state of the contract
    let tx = contract.call_with_confirmations(
        "followRegister", 
        (   first_claimer,
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

pub async fn withdraw(
    raw_account: [u8; 20], 
    raw_contract_address: [u8; 20], 
    abi: String,
    raw_first_claimer: [u8; 20],
    index: u128,
    amount_withdraw: U256
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
    let first_claimer = Address::from_slice(&raw_first_claimer);
    println!("value to be withdrawn is: {:#x}", amount_withdraw);
    // Change state of the contract
    let tx = contract.call_with_confirmations(
        "withdraw", 
        (   first_claimer,
            index,
            amount_withdraw,
        ),
        account, 
        Options::with(
            |opt| opt.gas = Some(3_000_000.into())
        ), 
        1)
        .await?;
    println!("TxHash: {:?}", tx);
    Ok(())
}

pub async fn updateek(
    raw_account: [u8; 20], 
    raw_contract_address: [u8; 20], 
    abi: String,
    raw_first_claimer: [u8; 20],
    ek: U256
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
    let first_claimer = Address::from_slice(&raw_first_claimer);
    println!("ek to be updated is: {:#x}", ek);
    // Change state of the contract
    let tx = contract.call_with_confirmations(
        "updateEkByAddr", 
        (   first_claimer,
            ek,
        ),
        account, 
        Options::with(
            |opt| opt.gas = Some(3_000_000.into())
        ), 
        1)
        .await?;
    println!("TxHash: {:?}", tx);
    Ok(())
}

pub async fn lookup_balance(
    raw_contract_address: [u8; 20], 
    abi: String,
    raw_first_claimer: [u8; 20],
    index: u128
) -> web3::contract::Result<U256> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    let json = File::open(abi).unwrap();
    let abi_json = ethabi::Contract::load(json).unwrap();
    let contract_address = Address::from_slice(&raw_contract_address);
    let contract = Contract::new(web3.eth(), contract_address, abi_json);
    println!("Deployed at: {:?}", contract.address());

    let first_claimer = Address::from_slice(&raw_first_claimer);
    // Change state of the contract
    let result = contract.query("lookUpBalance",(first_claimer,index,), None, Options::default(), None);
    let mybalance: U256 = result.await?;
    println!("Balance in contract: {:#x}", mybalance);
    Ok(mybalance)
}

pub async fn lookup_balance_byaddr_and_check(
    raw_contract_address: [u8; 20], 
    abi: String,
    raw_first_claimer: [u8; 20],
    raw_addr: [u8; 20],
    amount: u32,
) -> web3::contract::Result<U256> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    let json = File::open(abi).unwrap();
    let abi_json = ethabi::Contract::load(json).unwrap();
    let contract_address = Address::from_slice(&raw_contract_address);
    let contract = Contract::new(web3.eth(), contract_address, abi_json);
    println!("Deployed at: {:?}", contract.address());

    let first_claimer = Address::from_slice(&raw_first_claimer);
    let addr = Address::from_slice(&raw_addr);
    // Change state of the contract
    let result = contract.query("lookUpBalanceByAddr",(first_claimer,addr,), None, Options::default(), None);
    let mybalance: U256 = result.await?;
    println!("Balance in contract: {:#x}", mybalance);
    if mybalance.low_u32() >= amount {
        Ok(mybalance)
    }else{
        Err(InvalidOutputType("balance is not enough".to_string()))
    }
}

pub async fn lookup_ek_byaddr_and_check(
    raw_contract_address: [u8; 20], 
    abi: String,
    raw_first_claimer: [u8; 20],
    raw_addr: [u8; 20],
    ek: U256,
) -> web3::contract::Result<U256> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    let json = File::open(abi).unwrap();
    let abi_json = ethabi::Contract::load(json).unwrap();
    let contract_address = Address::from_slice(&raw_contract_address);
    let contract = Contract::new(web3.eth(), contract_address, abi_json);
    println!("Deployed at: {:?}", contract.address());

    let first_claimer = Address::from_slice(&raw_first_claimer);
    let addr = Address::from_slice(&raw_addr);
    // Change state of the contract
    let result = contract.query("lookUpEkByAddr",(first_claimer,addr,), None, Options::default(), None);
    let myek: U256 = result.await?;
    println!("Ek in contract: {:#x}", myek);
    if myek == ek {
        Ok(myek)
    }else{
        Err(InvalidOutputType("ek does not match".to_string()))
    }
}

pub async fn lookup_noofclaimers(
    raw_contract_address: [u8; 20], 
    abi: String,
    raw_first_claimer: [u8; 20]
) -> web3::contract::Result<U256> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    let json = File::open(abi).unwrap();
    let abi_json = ethabi::Contract::load(json).unwrap();
    let contract_address = Address::from_slice(&raw_contract_address);
    let contract = Contract::new(web3.eth(), contract_address, abi_json);
    println!("Deployed at: {:?}", contract.address());

    let first_claimer = Address::from_slice(&raw_first_claimer);
    // Change state of the contract
    let result = contract.query("lookUpNoOfClaimers",(first_claimer,), None, Options::default(), None);
    let mynoofclaimers: U256 = result.await?;
    println!("NoOfClaimers in contract: {:?}", mynoofclaimers);
    Ok(mynoofclaimers)
}

pub async fn transferfunc(
    raw_account: [u8; 20], 
    raw_contract_address: [u8; 20], 
    abi: String,
    senders: Vec<[u8;20]>,
    receivers: Vec<[u8;20]>,
    noofclaimers: u128,
    amount: u32,
    v: Vec<u8>,
    r: Vec<U256>,
    s: Vec<U256>,
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

    let i_senders: Vec<Token> = senders.iter().map(|i| Address::from_slice(i).into_token()).collect();
    let i_receivers: Vec<Token> = receivers.iter().map(|i| Address::from_slice(i).into_token()).collect();
    let i_v: Vec<Token> = v.iter().map(|i| i.into_token()).collect();
    let i_r: Vec<Token> = r.iter().map(|i| i.into_token()).collect();
    let i_s: Vec<Token> = s.iter().map(|i| i.into_token()).collect();

    //Change state of the contract
    let tx = contract.call_with_confirmations(
        "TransferFunc", 
        (
            i_senders,
            i_receivers,
            noofclaimers,
            amount,
            i_v,
            i_r,
            i_s,
        ),
        account, 
        Options::with(
            |opt| opt.gas = Some(3_000_000.into())
        ), 
        1)
        .await?;
    println!("TxHash: {:?}", tx);
    Ok(())
}

pub async fn check_receiver_balance(
    raw_account: [u8; 20],
) -> web3::contract::Result<()> {
    let _ = env_logger::try_init();
    let transport = web3::transports::Http::new("http://localhost:8545")?;
    let web3 = web3::Web3::new(transport);
    // Get current balance
    let account = Address::from_slice(&raw_account);
    let balance = web3.eth().balance(account, None).await?;
    println!("Account is {:#X}, Balance: {}", account, balance);
    Ok(())
}

#[test]
fn prepare_test() {
    use tokio2::runtime::Runtime;
    let mut rt = Runtime::new().unwrap();
    let predefined_contract_address = [238, 50, 245, 211, 24, 183, 155, 77, 119, 157, 219, 123, 251, 69, 118, 145, 249, 18, 187, 246];
    rt.block_on(devdeploy(
        [0x77,0x40,0x62,0x7c,0x47,0x1d,0x18,0x44,0x01,0xa1,0x17,0xcd,0xA2,0xAf,0x5c,0x20,0xb2,0x14,0x15,0xC9],
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.bin".to_string(),
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
    )).unwrap();
    rt.block_on(init_register(
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09], 
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        1716449919_u128,
        1816449919_u128,
        1916449919_u128,
        0x7F000002_u32,
        3000_u16,
        U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64]),
    )).unwrap();
    rt.block_on(follow_register(
        [0x44,0xde,0x1f,0xaA,0xa2,0xFc,0x62,0x27,0x05,0x00,0xBe,0xA1,0xde,0x45,0x71,0x6f,0xf3,0x2F,0xc9,0x45], 
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09], 
        U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64]),
    )).unwrap();    
    rt.block_on(follow_register(
        [0x0D,0x1e,0x34,0x36,0xfe,0xB9,0xe4,0x84,0x30,0x43,0xc3,0x1B,0x17,0xC3,0x95,0xA4,0x61,0x0e,0x00,0x60], 
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09], 
        U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64]),
    )).unwrap();    
}

#[test]
fn register_test() {
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
        3000_u16,
        U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64]),
    )).unwrap();
    rt.block_on(follow_register(
        [0x44,0xde,0x1f,0xaA,0xa2,0xFc,0x62,0x27,0x05,0x00,0xBe,0xA1,0xde,0x45,0x71,0x6f,0xf3,0x2F,0xc9,0x45], 
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09], 
        U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64]),
    )).unwrap();
    rt.block_on(lookup_balance(
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
        1_u128,
    )).unwrap();
    rt.block_on(lookup_noofclaimers(
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09]
    )).unwrap();
    rt.block_on(transferfunc(
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09], 
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        vec![
            [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
            [0x44,0xde,0x1f,0xaA,0xa2,0xFc,0x62,0x27,0x05,0x00,0xBe,0xA1,0xde,0x45,0x71,0x6f,0xf3,0x2F,0xc9,0x45]
        ],
        vec![
            [0xc5,0x57,0xB5,0x3C,0xAa,0x46,0xc9,0xaA,0xE2,0x32,0x12,0x94,0xF0,0x69,0x59,0xCb,0xa7,0xe1,0x85,0x52],
            [0x9D,0x4c,0x42,0xcd,0xE9,0x74,0xA2,0xdF,0x22,0xDF,0x71,0x03,0xB7,0x46,0x9f,0xdb,0x28,0xe0,0x06,0xA6]
        ],

        2_u128,
        //U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64]),
        0xff_u32,
        vec![1_u8, 2_u8],
        vec![U256([0x00_u64,0xFF_u64,0xFF_u64,0xFF_u64]), U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64])],
        vec![U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64]), U256([0x00_u64,0xFF_u64,0xFF_u64,0xFF_u64])],
    )).unwrap();
}

#[test]
fn withdraw_test() {
    use tokio2::runtime::Runtime;
    let mut rt = Runtime::new().unwrap();
    let predefined_contract_address = [238, 50, 245, 211, 24, 183, 155, 77, 119, 157, 219, 123, 251, 69, 118, 145, 249, 18, 187, 246];
    // rt.block_on(init_register(
    //     [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09], 
    //     predefined_contract_address,
    //     "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
    //     1716449919_u128,
    //     1816449919_u128,
    //     1916449919_u128,
    //     0x7F000002_u32,
    //     3000_u16,
    //     U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64]),
    // )).unwrap();
    // rt.block_on(follow_register(
    //     [0x44,0xde,0x1f,0xaA,0xa2,0xFc,0x62,0x27,0x05,0x00,0xBe,0xA1,0xde,0x45,0x71,0x6f,0xf3,0x2F,0xc9,0x45], 
    //     predefined_contract_address,
    //     "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
    //     [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
    //     U256([0xFF_u64,0x00_u64,0x00_u64,0x00_u64]),
    // )).unwrap();
    // rt.block_on(lookup_balance( 
    //     predefined_contract_address,
    //     "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
    //     [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
    //     1_u128,
    // )).unwrap();
    rt.block_on(withdraw(
        [0x44,0xde,0x1f,0xaA,0xa2,0xFc,0x62,0x27,0x05,0x00,0xBe,0xA1,0xde,0x45,0x71,0x6f,0xf3,0x2F,0xc9,0x45], 
        predefined_contract_address,
        "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
        [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
        1_u128,
        U256([0x0F_u64,0x00_u64,0x00_u64,0x00_u64]),
    )).unwrap();
    // rt.block_on(lookup_balance(
    //     predefined_contract_address,
    //     "/Users/zandent/Files/csc2125/ETH_Transfer_Shuffle/build/TrasnsferHelper.abi".to_string(),
    //     [0x9c,0xE7,0xd1,0xf9,0x76,0xc2,0xf6,0xd0,0x8D,0xB1,0x9D,0x09,0x1f,0x41,0xd1,0x18,0x9f,0x3A,0xc4,0x09],
    //     1_u128,
    // )).unwrap();
}
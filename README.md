# Off-chain Eth Shuffle Protocol

## Testing
Install ganache-cli
To run test node
```
ganache-cli -b 3 -m "hamster coin cup brief quote trick stove draft hobby strong caught unable"
```
To deploy by developer (recommended)
```
./target/*/devdeploy --abi <abs path to TrasnsferHelper.abi> --bin <abs path to TrasnsferHelper.bin>
```

Testing:
```
cargo test prepare_test -- --nocapture
./target/debug/relaysrv -n 3 -a 127.0.0.1 -p 5000
cargo test first_client_test -- --nocapture
cargo test second_client_test -- --nocapture
cargo test third_client_test -- --nocapture
```
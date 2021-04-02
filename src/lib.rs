pub mod comm;

pub use comm::*;

pub const DEFAULT_PORT: &str = "9999";
pub const DEFAULT_ABI: &str = include_str!("../ETH_Transfer_Shuffle/build/TrasnsferHelper.abi");

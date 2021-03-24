//! # Relay Server
//! 
//! Implements a routing server to be used along with the EthShuffle. 

use bincode::{deserialize_from, serialize};
use bytes::Bytes;
use clap::{value_t, App, Arg};
use ethshuffle_rs::messages::{Message, RelayMessage};
use futures::{future::join_all, prelude::*, stream::select_all};
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use tokio1::{net::TcpListener, runtime::Runtime};
use tokio_util::codec::LengthDelimitedCodec;

const DEFAULT_PORT: &str = "9999";


fn main() -> Result<(), Box<dyn Error>> {
    
    Ok(())
}

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

async fn async_main(ip: IpAddr, p: u16, n: u16) -> io::Result<()> {
    let listener = TcpListener::bind((ip, p)).await?;
    let mut clients_rd = Vec::with_capacity(n as usize);
    let mut clients_wr = HashMap::with_capacity(n as usize);

    // Build a `length_delimited` codec: serialized data is prefixed with its length
    let codec = *LengthDelimitedCodec::builder()
        .big_endian()
        .max_frame_length(4096)
        .length_field_length(4);

    for i in 0..n {
        // NOTE may use `client_sock` as identifier
        let (client_stream, _client_sock) = listener.accept().await?;

        let (rd, wr) = client_stream.into_split();

        clients_rd.push(codec.new_read(rd));
        clients_wr.insert(i as u32, codec.new_write(wr));
    }

    // announce the clients their ids
    let mut announcements = Vec::with_capacity(n as usize);

    for (&id, client) in clients_wr.iter_mut() {
        let msg = Message::AnnounceId(id);
        let r_msg = RelayMessage::new(id, msg);
        // Can unwrap, the data is safe
        let serialized = serialize(&r_msg).unwrap();
        announcements.push(client.send(Bytes::from(serialized)));
    }

    // Wait until all the clients learn their
    join_all(announcements).await;

    // Merge all client read streams into one stream
    let mut rds = select_all(clients_rd.into_iter());

    // Run stream to exhaustion
    while let Some(item) = rds.try_next().await? {
        let r_msg: RelayMessage = if let Ok(msg) = deserialize_from(&item[..]) {
            msg
        } else {
            eprintln!("ERROR: incorrect incoming message");
            continue;
        };

        let item = item.freeze();

        // We use `id` 0 to refer to broadcasting
        if r_msg.to_id == 0 {
            for client in clients_wr.values_mut() {
                // FIXME This blocks the execution. Should spawn a task here. However, may
                // try to send different messages into a single stream concurrently, which
                // might cause collision
                client.send(item.clone()).await?;
            }
        } else if let Some(client) = clients_wr.get_mut(&r_msg.to_id) {
            // FIXME This blocks the execution. Should spawn a task here.
            client.send(item).await?;
        } else {
            eprintln!("ERROR: reference to unknown client");
            continue;
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let matches = App::new("EthShuffle Relay Server")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Relay Server implementation to be used with EthShuffle.")
        .arg(
            Arg::with_name("addr")
                .help("binding address")
                .long("addr")
                .short("a")
                .takes_value(true)
                .value_name("IP_ADDR")
                .required(true)
                .default_value("0.0.0.0")
                .validator(|x| match IpAddr::from_str(x.as_str()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("incorrect IP address")),
                }),
        )
        .arg(
            Arg::with_name("port")
                .help("binding port")
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
            // FIXME omit this parameter and make implementation work with any number of participants
            Arg::with_name("#participants")
                .help("the number of participants in the shuffling protocols")
                .long("participants")
                .short("n")
                .required(true)
                .takes_value(true)
                .validator(|x| match x.parse::<u16>() {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Incorrect number of participants")),
                }),
        )
        .get_matches();
    let ip = IpAddr::from_str(matches.value_of("addr").unwrap()).unwrap();
    let p = value_t!(matches.value_of("port"), u16).unwrap();
    let n = value_t!(matches.value_of("#participants"), u16).unwrap();

    let rt = Runtime::new().unwrap();
    rt.block_on(async_main(ip, p, n))?;

    Ok(())
}

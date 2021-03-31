//! # Relay Server
//!
//! Implements a routing server to be used along with the EthShuffle.

use bincode::deserialize_from;
use clap::{value_t, App, Arg};
use ethshuffle_rs::messages::{Message, RelayMessage};
use ethshuffle_rs::DEFAULT_PORT;
use futures::{prelude::*, stream::select_all};
use std::collections::HashMap;
use std::error::Error;
use std::fmt::Debug;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use tokio1::{net::TcpListener, runtime::Runtime};
use tokio_util::codec::LengthDelimitedCodec;

async fn async_main(ip: IpAddr, p: u16, n: u16) -> io::Result<()> {
    let listener = TcpListener::bind((ip, p)).await?;
    let mut clients_rd = Vec::with_capacity(n as usize);
    let mut clients_wr_temp = Vec::with_capacity(n as usize);

    // Build a `length_delimited` codec: serialized data is prefixed with its length
    let codec = *LengthDelimitedCodec::builder()
        .big_endian()
        .max_frame_length(4096)
        .length_field_length(4);

    for _ in 0..n {
        let (client_stream, _client_sock) = listener.accept().await?;

        let (rd, wr) = client_stream.into_split();

        clients_rd.push(codec.new_read(rd));
        clients_wr_temp.push(codec.new_write(wr));
    }

    let mut clients_rd_to_id = HashMap::with_capacity(n as usize);

    // Ephemeral key announcement. We learn the ids of the clients for routing simultaneously
    for (i, client_rd) in clients_rd.iter_mut().enumerate() {
        if let Some(item) = client_rd.try_next().await? {
            // deserialize the relay messages
            let r_msg: RelayMessage = if let Ok(msg) = deserialize_from(&item[..]) {
                msg
            } else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "the message format for key exchange is incorrect",
                ));
            };

            // we expect the key announcement message from the clients
            match r_msg.msg {
                Message::AnnounceEk { id, .. } => {
                    clients_rd_to_id.insert(i, id);
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "the message format for key exchange is incorrect",
                    ))
                }
            }

            // now we need to broadcast the received key announcement to all other clients
            broadcast(clients_wr_temp.iter_mut(), item.freeze()).await?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "client unexpectedly closed the stream",
            ));
        }
    }

    // Build the routing table: from client id to the stream
    let mut clients_wr: HashMap<_, _> = clients_wr_temp
        .into_iter()
        .enumerate()
        .map(|(i, cl_w)| (clients_rd_to_id[&i], cl_w))
        .collect();

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
            broadcast(
                clients_wr
                    .iter_mut()
                    .filter_map(|(&id, cl)| if id != r_msg.from_id { Some(cl) } else { None }),
                item,
            )
            .await?;
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

/// Broadcast the `data` to all clients in `to_clients`
async fn broadcast<I, B, S, E>(to_clients: I, data: B) -> io::Result<()>
where
    I: Iterator<Item = S>,
    B: Clone,
    S: Sink<B, Error = E> + Unpin,
    E: Debug,
{
    for mut client in to_clients {
        // FIXME This blocks the execution. Should spawn a task here. However, may
        // try to send different messages into a single stream concurrently, which
        // might cause collision
        client.send(data.clone()).await.map_err(|e| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                format!("could not broadcast to client: {:?}", e),
            )
        })?;
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
                .required(false)
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
                .required(false)
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
                .value_name("#PARTICIPANTS")
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

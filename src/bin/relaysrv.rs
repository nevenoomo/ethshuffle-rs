use clap::{value_t, App, Arg};
use ethshuffle_rs::messages;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::string::ToString;
use tokio::{net::TcpListener, runtime::Runtime, io::AsyncWriteExt};
use tokio_serde_bincode::{ReadBincode, WriteBincode};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

const DEFAULT_PORT: &str = "9999";

async fn async_main(ip: IpAddr, p: u16, n: u16) -> io::Result<()> {
    let listener = TcpListener::bind((ip, p)).await?;
    let mut clients = HashMap::with_capacity(n as usize);

    let codec = LengthDelimitedCodec::builder()
        .big_endian()
        .max_frame_length(4096)
        .length_field_length(4)
        .clone();

    for i in 0..n {
        // NOTE may use `client_sock` as identifier
        let (client_stream, _client_sock) = listener.accept().await?;
        // TODO use `select_all()` to iterate over streams and output to sinks

        clients.insert(i, codec.new_framed(client_stream));
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

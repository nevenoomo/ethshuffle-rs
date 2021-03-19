use clap::{value_t, App, Arg};
use ethshuffle_rs::messages;
use std::error::Error;
use std::io;
use std::net::IpAddr;
use std::str::FromStr;
use std::string::ToString;
use tokio::{net::TcpListener, runtime::Runtime};

const DEFAULT_PORT: u16 = 9999;

async fn async_main(ip: IpAddr, p: u16, n: u16) -> io::Result<()> {
    let listener = TcpListener::bind((ip, p)).await?;
    let mut clients = Vec::with_capacity(n as usize);

    for _ in 0..n {
        let (client_stream, client_sock) = listener.accept().await?;
        // TODO convert TcpStream into tokio-serde bincode decoder/encoder
        // then use `select_all()` to iterate over streams and output to sinks
        // NOTE don't forget to set `length_delimited` to use only 4 bytes 
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
                .default_value(&DEFAULT_PORT.to_string())
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

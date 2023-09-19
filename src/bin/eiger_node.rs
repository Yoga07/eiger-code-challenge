use clap::{App, Arg};
use eiger_code_challenge::node::Node;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    // Define the command-line interface
    let matches = App::new("Eiger Handshake Node")
        .author("Yogesh")
        .about("A simple Rust program with performs Handshakes with Casper P2P nodes")
        .arg(
            Arg::with_name("our_address")
                .help("SocketAddress for this to node to bind to")
                .short("addr")
                .long("our_address")
                .value_name("SOCKET_ADDR")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("chainspec_path")
                .help("Path to chainspec.toml file")
                .short("c")
                .long("chainspec")
                .value_name("PATH")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("log_to_file")
                .help("Writes logs to a file on a rolling basis")
                .short("l")
                .long("log_to_file")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("peer_address")
                .help("SocketAddress of the peer we'll be connecting to")
                .short("p")
                .long("peer_address")
                .value_name("SOCKET_ADDR")
                .takes_value(true)
                .required(false),
        )
        .get_matches();

    // Access and process the command-line arguments
    let our_address_str = matches
        .value_of("our_address")
        .expect("SocketAddress for the node was not passed");

    let mut bootstrap_addrs = vec![];

    if let Some(peer_address_str) = matches.value_of("peer_address") {
        bootstrap_addrs.push(
            SocketAddr::from_str(peer_address_str)
                .expect("Error parsing string as std::net::SocketAddr for peer"),
        )
    }

    let chainspec_path = matches
        .value_of("chainspec_path")
        .expect("Path to chainspec.toml was not provided");

    let log_to_file = matches.is_present("log_to_file");

    let our_address = SocketAddr::from_str(our_address_str)
        .expect("Error parsing string as std::net::SocketAddr");

    match Node::new(
        our_address,
        bootstrap_addrs,
        PathBuf::from(chainspec_path),
        log_to_file,
    )
    .await
    {
        Ok(node) => {
            node.start_event_loop().await;
        }
        Err(e) => {
            println!("Error starting node {e:?}");
        }
    }
}

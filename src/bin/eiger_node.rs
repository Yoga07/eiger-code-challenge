use eiger_code_challenge::node::Node;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    let our_address = SocketAddr::from_str("127.0.0.1:5001")
        .expect("Error parsing string as std::net::SocketAddr");

    let peer_address = SocketAddr::from_str("127.0.0.1:34553")
        .expect("Error parsing string as std::net::SocketAddr");

    match Node::new(our_address).await {
        Ok(node) => {
            node.start_event_loop().await;
            node.connect_to(peer_address).await.unwrap();
            node.send_handshake_to::<Vec<u8>>(peer_address).await.unwrap();
            loop {
                sleep(Duration::from_secs(1)).await;
            }
        }
        Err(e) => {
            println!("Error starting node {e:?}");
        }
    }
}

use eiger_code_challenge::node::Node;
use std::net::SocketAddr;
use std::str::FromStr;

#[tokio::main]
async fn main() {
    let our_address = SocketAddr::from_str("127.0.0.1:5001").unwrap();

    match Node::new(our_address).await {
        Ok(node) => {
            node.start_event_loop().await;
        }
        Err(e) => {
            println!("Error starting node {e:?}");
        }
    }
}

use bytes::Bytes;
use eiger_code_challenge::node::Node;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    let address1 = SocketAddr::from_str("127.0.0.1:5000").unwrap();
    let _handle = tokio::spawn(async move {
        let _node = match Node::new(address1).await {
            Ok(node) => loop {},
            Err(e) => {
                println!("Error starting node {e:?}");
                return;
            }
        };
    });

    let address2 = SocketAddr::from_str("127.0.0.1:5001").unwrap();
    // let handle = tokio::spawn(async move {
    let _node2 = match Node::new(address2).await {
        Ok(mut node2) => {
            println!("looping 2");
            node2.connect_to(address1).await;
            loop {
                node2
                    .send_message_to(address1, Bytes::from("Hi there!"))
                    .await
                    .unwrap();
                sleep(Duration::from_secs(5)).await;
            }
        }
        Err(e) => {
            println!("Error starting node {e:?}");
            return;
        }
    };
    // });
}

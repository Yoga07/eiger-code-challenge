use eiger_code_challenge::node::Node;
use eiger_code_challenge::Event;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    let address1 = SocketAddr::from_str("127.0.0.1:5000").unwrap();
    let address2 = SocketAddr::from_str("127.0.0.1:5001").unwrap();

    let _handle = tokio::spawn(async move {
        let _node = match Node::new(address1, vec![address2]).await {
            Ok(node) => loop {
                node.start_event_loop().await;
                node.begin_handshake(address2).await.unwrap();
                sleep(Duration::from_secs(1)).await;
            },
            Err(e) => {
                println!("Error starting node {e:?}");
                return;
            }
        };
    });

    let _node2 = match Node::new(address2, vec![address1]).await {
        Ok(mut node2) => {
            node2.start_event_loop().await;
            node2.connect_to(address1).await;
            loop {
                node2
                    .send_event_to(address1, Event::Generic("Hi there!".to_string()))
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
}

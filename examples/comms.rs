use std::fmt::{Display, Formatter};
use eiger_code_challenge::node::Node;
use std::net::SocketAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio::time::sleep;
use eiger_code_challenge::casper_types::message::Payload;

#[tokio::main]
async fn main() {
    let address1 = SocketAddr::from_str("127.0.0.1:34553").unwrap();
    let address2 = SocketAddr::from_str("127.0.0.1:5001").unwrap();

    // println!("Starting node 1");
    // let _handle = tokio::spawn(async move {
    //     println!("started node 1 thread");
    //     match Node::new(address1, vec![]).await {
    //         Ok(node) => {
    //             node.start_event_loop().await;
    //             loop {
    //                 // Wait for the other node to set up
    //                 sleep(Duration::from_secs(5)).await;
    //             }
    //         }
    //         Err(e) => {
    //             println!("Error starting node {e:?}");
    //         }
    //     }
    // });
    //
    // loop {
    //     sleep(Duration::from_secs(5)).await;
    // }

    let node = match Node::new(address2, vec![]).await {
        Ok(mut node2) => {
            println!("started node 2");
            node2
            // node2.start_event_loop().await;
            // node2.connect_to(address1).await.unwrap();
        }
        Err(e) => {
            println!("Error starting node {e:?}");
            return
        }
    };

    loop {
        let _ = node.send_handshake_to::<Vec<u8>>(address1).await;
        // node2
        //     .send_event_to(address1, Event::Generic("Hi there!".to_string()))
        //     .await
        //     .unwrap();
        sleep(Duration::from_secs(1)).await;
    }
}

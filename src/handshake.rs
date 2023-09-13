use crate::error::Result;
use bincode::serialize;
use blsttc::{PublicKey, SecretKey};
use bytes::Bytes;
use std::net::SocketAddr;

use crate::event::{Event, HandShakeMessage, HandShakeResponder, HandShakeSender};
use crate::node::Node;

pub struct HandshakeHandler {
    ephemeral_keypair: Option<(PublicKey, SecretKey)>,
}

impl HandshakeHandler {
    pub fn new() -> Self {
        HandshakeHandler {
            ephemeral_keypair: None,
        }
    }
}

impl Node {
    pub async fn begin_handshake(&self, node_addr: SocketAddr) -> Result<()> {
        let ephemeral_sk = SecretKey::random();
        let ephemeral_pk = ephemeral_sk.public_key();

        self.handshake_handler.write().await.ephemeral_keypair = Some((ephemeral_pk, ephemeral_sk));

        // Initiate the XX pattern
        let msg = Event::Handshake(HandShakeMessage::Sender(HandShakeSender::EphemeralPK(
            ephemeral_pk,
        )));
        self.send_event_to(node_addr, msg).await
    }

    pub async fn handle_handshake(&self, message: HandShakeMessage) {
        match message {
            HandShakeMessage::Sender(sender_msg) => match sender_msg {
                HandShakeSender::EphemeralPK(e_pub) => {}
            },
            HandShakeMessage::Responder(responder_msg) => match responder_msg {
                HandShakeResponder::EphemeralPK(e_pub) => {}
                HandShakeResponder::Static() => {}
            },
        }
    }
}

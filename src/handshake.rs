use crate::error::{Error, Result};
use aes_gcm::KeyInit;
use bincode::serialize;
use bytes::Bytes;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::Sender;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use crate::event::{Event, HandShakeMessage, HandShakeResponder, HandShakeSender, LocalEvent};
use crate::node::Node;

pub struct HandshakeHandler {
    ongoing: BTreeMap<SocketAddr, HandShakeSession>,
    static_keypair: (PublicKey, StaticSecret),
}

pub struct HandShakeSession {
    peer_addr: SocketAddr,
    peer_ephemeral_pk: Option<PublicKey>,
    peer_static_key: Option<PublicKey>,
    our_ephemeral_keypair: Option<(PublicKey, EphemeralSecret)>,
    // Diffie-Hellman Keys
    ephemeral_shared_secret: Option<SharedSecret>,
}

impl HandshakeHandler {
    pub fn new() -> Self {
        let static_sk = StaticSecret::random();
        let static_pk = PublicKey::from(&static_sk);

        HandshakeHandler {
            ongoing: BTreeMap::new(),
            static_keypair: (static_pk, static_sk),
        }
    }
}

impl Node {
    pub async fn begin_handshake(&self, node_addr: SocketAddr) -> Result<()> {
        println!("Starting Handshake to {node_addr:?}");
        let ephemeral_sk = EphemeralSecret::random();
        let ephemeral_pk = PublicKey::from(&ephemeral_sk);

        let hss = HandShakeSession {
            peer_addr: node_addr,
            peer_ephemeral_pk: None,
            peer_static_key: None,
            our_ephemeral_keypair: Some((ephemeral_pk, ephemeral_sk)),
            ephemeral_shared_secret: None,
        };

        // Insert into our ongoing handshake sessions
        let _ = self
            .handshake_handler
            .write()
            .await
            .ongoing
            .insert(node_addr, hss);

        // Initiate the XX pattern
        let msg = Event::LocalEvent(LocalEvent::SendEventTo(
            node_addr,
            Box::new(Event::Handshake(HandShakeMessage::Sender(
                HandShakeSender::EphemeralPK(ephemeral_pk.as_bytes().clone()),
            ))),
        ));

        self.event_tx
            .send((self.our_address(), msg))
            .await
            .map_err(|e| Error::Generic(format!("Event channel closed {e:?}")))
    }

    pub async fn handle_handshake(
        &self,
        peer: SocketAddr,
        message: HandShakeMessage,
        event_tx: Sender<(SocketAddr, Event)>,
    ) {
        match message {
            HandShakeMessage::Sender(sender_msg) => match sender_msg {
                HandShakeSender::EphemeralPK(bytes) => {
                    let peer_e_pub = PublicKey::from(bytes);

                    // Generate our e_pub to be sent
                    let our_ephemeral_sk = EphemeralSecret::random();
                    let our_ephemeral_pk = PublicKey::from(&ephemeral_sk);

                    let mut hss = HandShakeSession {
                        peer_addr: peer,
                        peer_ephemeral_pk: Some(peer_e_pub),
                        peer_static_key: None,
                        our_ephemeral_keypair: Some((our_ephemeral_pk, our_ephemeral_sk)),
                        ephemeral_shared_secret: None,
                    };

                    let msg = Event::LocalEvent(LocalEvent::SendEventTo(
                        peer,
                        Box::new(Event::Handshake(HandShakeMessage::Responder(
                            HandShakeResponder::EphemeralPK(our_ephemeral_pk.as_bytes().clone()),
                        ))),
                    ));

                    if let Err(e) = event_tx
                        .send((self.our_address(), msg))
                        .await
                        .map_err(|e| Error::Generic(format!("Event channel closed {e:?}")))
                    {
                        println!("Error sending our e_pub to sender {e:?}");
                        return;
                    }

                    // Start Diffie-Hellman of ephemeral keys
                    let ephemeral_shared_secret = our_ephemeral_sk.diffie_hellman(&peer_e_pub);

                    // Split the shared secret into key and nonce
                    let (encryption_key, nonce) = ephemeral_shared_secret.to_bytes().split_at(16); // You can adjust the sizes as needed
                    let cipher = match aes_gcm::Aes256Gcm::new_from_slice(encryption_key) {
                        Ok(cipher) => cipher,
                        Err(e) => {
                            println!("Error creating cipher from ephemeral_shared_secret");
                            return;
                        }
                    };

                    // Insert into our ongoing handshake sessions
                    let _ = self
                        .handshake_handler
                        .write()
                        .await
                        .ongoing
                        .insert(peer, hss);
                }
            },
            HandShakeMessage::Responder(responder_msg) => match responder_msg {
                HandShakeResponder::EphemeralPK(e_pub) => {}
                HandShakeResponder::Static() => {}
            },
        }
    }
}

use crate::error::{Error, Result};
use aes_gcm::aead::{Aead, Nonce};
use aes_gcm::{Aes256Gcm, KeyInit};
use bincode::serialize;
use bytes::Bytes;
use sha3::digest::Output;
use sha3::Sha3_256;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::Sender;
use tracing::error;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use crate::event::{Event, HandShakeMessage, HandShakeResponder, HandShakeSender, LocalEvent};
use crate::node::Node;
use crate::utils::{hash, Hash};

pub const HANDHSHAKE_PATTERN: &str = "NOISE_XX_SHA256";

pub const INITIAL_NONCE: u8 = 0;

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
    mix_key: Option<Aes256Gcm>,
    nonce: u8,
    // Session specifics
    session_hash: Hash,
}

impl HandShakeSession {
    pub fn perform_ephemeral_diffie_hellman(&mut self, their_pk: PublicKey) -> Result<()> {
        self.peer_ephemeral_pk = Some(their_pk);

        // Start Diffie-Hellman of ephemeral keys
        let e_keypair = self.our_ephemeral_keypair.take();

        if let Some((e_pub, e_sk)) = e_keypair {
            let ephemeral_shared_secret = e_sk.diffie_hellman(&their_pk);

            // Split the shared secret into key and nonce
            let nonce = hash(ephemeral_shared_secret.as_bytes().split_at(16).1)[0]; // First byte of the hash of encyrption key is the nonce

            self.nonce = nonce;

            let cipher =
                match aes_gcm::Aes256Gcm::new_from_slice(ephemeral_shared_secret.as_bytes()) {
                    Ok(cipher) => cipher,
                    Err(e) => {
                        println!("Error creating cipher from ephemeral_shared_secret");
                        return Err(Error::HandShake(
                            "Error creating cipher from ephemeral_shared_secret".to_string(),
                        ));
                    }
                };

            self.ephemeral_shared_secret = Some(ephemeral_shared_secret);

            self.mix_key = Some(cipher);
        } else {
            println!("Error when receiving Responder EphemeralPK: No self.ephemeral_sk found");
            return Err(Error::HandShake(
                "Error when receiving Responder EphemeralPK: No self.ephemeral_sk found"
                    .to_string(),
            ));
        }

        Ok(())
    }
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
            nonce: INITIAL_NONCE,
            mix_key: None,
            session_hash: hash(HANDHSHAKE_PATTERN.as_bytes()),
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
                    let our_ephemeral_pk = PublicKey::from(&our_ephemeral_sk);

                    let mut hss = HandShakeSession {
                        peer_addr: peer,
                        peer_ephemeral_pk: Some(peer_e_pub),
                        peer_static_key: None,
                        our_ephemeral_keypair: Some((our_ephemeral_pk, our_ephemeral_sk)),
                        ephemeral_shared_secret: None,
                        nonce: INITIAL_NONCE,
                        mix_key: None,
                        session_hash: hash(HANDHSHAKE_PATTERN.as_bytes()),
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

                    if hss.perform_ephemeral_diffie_hellman(peer_e_pub).is_err() {
                        return;
                    }

                    // Generate Static Key
                    let our_static_sk = StaticSecret::random();
                    let our_static_pk = PublicKey::from(&our_static_sk);

                    // TODO: Encrypt the Static PK

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
                HandShakeResponder::EphemeralPK(bytes) => {
                    let peer_e_pub = PublicKey::from(bytes);

                    // Since this is from the responder, we should already have a session going
                    let mut hss = match self.handshake_handler.write().await.ongoing.remove(&peer) {
                        Some(session) => session,
                        None => {
                            println!(
                                "Error when receiving Responder EphemeralPK. No session found"
                            );
                            return;
                        }
                    };

                    if hss.perform_ephemeral_diffie_hellman(peer_e_pub).is_err() {
                        return;
                    }

                    // Insert back into our ongoing handshake sessions
                    let _ = self
                        .handshake_handler
                        .write()
                        .await
                        .ongoing
                        .insert(peer, hss);
                }
                HandShakeResponder::Static() => {}
            },
        }
    }
}

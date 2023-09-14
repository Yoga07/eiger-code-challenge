use crate::error::{Error, Result};
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, AeadCore, Nonce};
use aes_gcm::{Aes256Gcm, KeyInit};
use bincode::{deserialize, serialize};
use bytes::Bytes;
use sha3::digest::Output;
use sha3::Sha3_256;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use tokio::sync::mpsc::Sender;
use tokio::time::{sleep, Duration};
use tracing::{error, info};
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret, StaticSecret};

use crate::event::{
    Event, HandShakeMessage, HandShakeResponder, HandShakeSender, LocalEvent, SessionState,
};
use crate::node::Node;
use crate::utils::{hash, Hash};

pub const HANDHSHAKE_PATTERN: &str = "NOISE_XX_SHA256";

pub const INITIAL_NONCE: [u8; 12] = [0u8; 12];

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
    nonce: Vec<u8>,
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
            let nonce = hash(ephemeral_shared_secret.as_bytes().split_at(16).1)[0..12].to_vec(); // First byte of the hash of encyrption key is the nonce
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
        let addr = self.our_address();
        let ephemeral_sk = EphemeralSecret::random();
        let ephemeral_pk = PublicKey::from(&ephemeral_sk);

        let hss = HandShakeSession {
            peer_addr: node_addr,
            peer_ephemeral_pk: None,
            peer_static_key: None,
            our_ephemeral_keypair: Some((ephemeral_pk, ephemeral_sk)),
            ephemeral_shared_secret: None,
            nonce: INITIAL_NONCE.to_vec(),
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

        println!("[{addr:?}] Sending e_pub to responder");

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

    pub async fn handle_handshake(&self, peer: SocketAddr, message: HandShakeMessage) {
        let addr = self.our_address();
        let mut hs_handler = self.handshake_handler.write().await;
        let event_tx = self.event_tx.clone();
        match message {
            HandShakeMessage::Sender(sender_msg) => match sender_msg {
                HandShakeSender::EphemeralPK(bytes) => {
                    let peer_e_pub = PublicKey::from(bytes);

                    println!("[{addr:?}] Received e_pub from Sender");

                    // Generate our e_pub to be sent
                    let our_ephemeral_sk = EphemeralSecret::random();
                    let our_ephemeral_pk = PublicKey::from(&our_ephemeral_sk);

                    let mut hss = HandShakeSession {
                        peer_addr: peer,
                        peer_ephemeral_pk: Some(peer_e_pub),
                        peer_static_key: None,
                        our_ephemeral_keypair: Some((our_ephemeral_pk, our_ephemeral_sk)),
                        ephemeral_shared_secret: None,
                        nonce: INITIAL_NONCE.to_vec(),
                        mix_key: None,
                        session_hash: hash(HANDHSHAKE_PATTERN.as_bytes()),
                    };

                    let msg = Event::LocalEvent(LocalEvent::SendEventTo(
                        peer,
                        Box::new(Event::Handshake(HandShakeMessage::Responder(
                            HandShakeResponder::EphemeralPK(our_ephemeral_pk.as_bytes().clone()),
                        ))),
                    ));

                    println!("[{addr:?}] Sending e_pub to Sender");
                    if let Err(e) = event_tx
                        .send((self.our_address(), msg))
                        .await
                        .map_err(|e| Error::Generic(format!("Event channel closed {e:?}")))
                    {
                        println!("Error sending our e_pub to sender {e:?}");
                        return;
                    }

                    println!("[{addr:?}] Running dhee");
                    if hss.perform_ephemeral_diffie_hellman(peer_e_pub).is_err() {
                        return;
                    }

                    let notifier = SessionState::EphemeralDHEEDone;
                    self.send_hs_notifier(&hss, event_tx.clone(), peer, notifier)
                        .await;

                    // Insert into our ongoing handshake sessions
                    let _ = hs_handler.ongoing.insert(peer, hss);
                }
            },
            HandShakeMessage::Responder(responder_msg) => match responder_msg {
                HandShakeResponder::EphemeralPK(bytes) => {
                    println!("[{addr:?}] Received e_pub from Responder");
                    let peer_e_pub = PublicKey::from(bytes);

                    println!("[{addr:?}] Running DHEE at Sender");
                    // Since this is from the responder, we should already have a session going
                    let mut hss = match hs_handler.ongoing.remove(&peer) {
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

                    println!("Inserting into our sessions");

                    // Insert back into our ongoing handshake sessions
                    let _ = hs_handler.ongoing.insert(peer, hss);

                    println!("DONE Inserting into our sessions");
                }
                HandShakeResponder::EncyptedStatic(their_enc_static) => {
                    println!("[{addr:?}] RECEIVED THEIR ENCRYPTED STATIC!!!!!!!!!!!!!!!!!!!");

                    let mut hss = match hs_handler.ongoing.remove(&peer) {
                        Some(session) => session,
                        None => {
                            println!(
                                "[{addr:?}] Error when receiving Responder Encrypted Static. No session found"
                            );
                            return;
                        }
                    };

                    // Decrypt their static key
                    let decrypted_key = if let Some(key) = hss.mix_key {
                        match key.decrypt(
                            GenericArray::from_slice(&hss.nonce),
                            their_enc_static.as_slice(),
                        ) {
                            Ok(enc_static_pk) => {
                                println!("[{addr:?}] DECRYPTED THEIR ENCRYPTED STATIC!!!!!!!!!!!!!!!!!!!");
                            }
                            Err(e) => {
                                println!("[{addr:?}] Error decrypting static pk {e:?}");
                            }
                        }
                    };
                }
            },
            HandShakeMessage::GenerateStaticKeysFor(handshake_peer) => {
                let mut hss = match hs_handler.ongoing.remove(&handshake_peer) {
                    Some(session) => session,
                    None => {
                        println!(
                            "[{addr:?}] Error when receiving Responder Encrypted Static. No session found"
                        );
                        return;
                    }
                };

                // Generate Static Key
                let our_static_sk = StaticSecret::random();
                let our_static_pk = PublicKey::from(&our_static_sk);
                let our_static_pk_bytes = our_static_pk.as_bytes().as_slice();

                let encrpyted_static_pk = if let Some(key) = &hss.mix_key {
                    match key.encrypt(GenericArray::from_slice(&hss.nonce), our_static_pk_bytes) {
                        Ok(enc_static_pk) => enc_static_pk,
                        Err(e) => {
                            println!("Error encrypting static pk {e:?}");
                            return;
                        }
                    }
                } else {
                    println!("No mixKey found. Need a mixKey for Encrypting Static key");
                    return;
                };

                println!("[{addr:?}] Sending enc_static_pk to Sender");
                let msg_b = Event::LocalEvent(LocalEvent::SendEventTo(
                    peer,
                    Box::new(Event::Handshake(HandShakeMessage::Responder(
                        HandShakeResponder::EncyptedStatic(encrpyted_static_pk),
                    ))),
                ));

                if let Err(e) = event_tx
                    .send((self.our_address(), msg_b))
                    .await
                    .map_err(|e| Error::Generic(format!("Event channel closed {e:?}")))
                {
                    println!("Error sending our e_pub to sender {e:?}");
                    return;
                }
            }
            HandShakeMessage::StateNotifier(payload) => {
                let mut hss = match hs_handler.ongoing.get(&peer) {
                    Some(session) => session,
                    None => {
                        println!(
                            "[{addr:?}] Error when receiving Responder Encrypted Static. No session found"
                        );
                        return;
                    }
                };

                // Decrypt the message
                let session_state = if let Some(key) = &hss.mix_key {
                    match key.decrypt(GenericArray::from_slice(&hss.nonce), payload.as_slice()) {
                        Ok(notifier) => {
                            let deserialized_state: SessionState =
                                if let Ok(state) = deserialize(&notifier) {
                                    state
                                } else {
                                    return;
                                };
                            println!("[{addr:?}] DECRYPTED NOTIFIER {deserialized_state:?}");
                            deserialized_state
                        }
                        Err(e) => {
                            println!("[{addr:?}] Error decrypting Notifier {e:?}");
                            return;
                        }
                    }
                } else {
                    println!("[{addr:?}] Error: mixKey missing during state msg decryption");
                    return;
                };

                self.handle_session_state(peer, session_state).await;
            }
        }
    }

    pub async fn handle_session_state(&self, peer: SocketAddr, session_state: SessionState) {
        let addr = self.our_address();
        match session_state {
            SessionState::EphemeralDHEEDone => {
                let msg = Event::LocalEvent(LocalEvent::HandleHandshakeEvent((
                    peer,
                    HandShakeMessage::GenerateStaticKeysFor(peer),
                )));

                println!("[{addr:?}] Sending NOTIFIER to Sender");
                if let Err(e) = self
                    .event_tx
                    .send((self.our_address(), msg))
                    .await
                    .map_err(|e| Error::Generic(format!("Event channel closed {e:?}")))
                {
                    println!("Error sending HS notifier to sender {e:?}");
                    return;
                }
            }
        }
    }

    pub async fn send_hs_notifier(
        &self,
        hss: &HandShakeSession,
        event_tx: Sender<(SocketAddr, Event)>,
        peer: SocketAddr,
        notifier: SessionState,
    ) {
        let addr = self.our_address();

        match serialize(&notifier) {
            Ok(serailized_notifier) => {
                let encrpyted_notifier = if let Some(key) = &hss.mix_key {
                    match key.encrypt(
                        GenericArray::from_slice(&hss.nonce),
                        serailized_notifier.as_slice(),
                    ) {
                        Ok(enc_notifier) => enc_notifier,
                        Err(e) => {
                            println!("Error encrypting static pk {e:?}");
                            return;
                        }
                    }
                } else {
                    println!("No mixKey found. Need a mixKey for Encrypting Notifier");
                    return;
                };

                let msg = Event::LocalEvent(LocalEvent::SendEventTo(
                    peer,
                    Box::new(Event::Handshake(HandShakeMessage::StateNotifier(
                        encrpyted_notifier,
                    ))),
                ));

                println!("[{addr:?}] Sending NOTIFIER to Sender");
                if let Err(e) = event_tx
                    .send((self.our_address(), msg))
                    .await
                    .map_err(|e| Error::Generic(format!("Event channel closed {e:?}")))
                {
                    println!("Error sending HS notifier to sender {e:?}");
                    return;
                }
            }
            Err(e) => {
                println!("Error serializing Notifier {e:?}");
                return;
            }
        }
    }
}

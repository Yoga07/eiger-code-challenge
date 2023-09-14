use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    Handshake(HandShakeMessage),
    Generic(String),
    LocalEvent(LocalEvent),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LocalEvent {
    SendEventTo(SocketAddr, Box<Event>),
    HandleHandshakeEvent((SocketAddr, HandShakeMessage)),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HandShakeMessage {
    Sender(HandShakeSender),
    Responder(HandShakeResponder),
    GenerateStaticKeysFor(SocketAddr),
    StateNotifier(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HandShakeSender {
    EphemeralPK([u8; 32]),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HandShakeResponder {
    EphemeralPK([u8; 32]),
    EncyptedStatic(Vec<u8>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SessionState {
    EphemeralDHEEDone,
}

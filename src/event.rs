use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use x25519_dalek::PublicKey;

#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    Handshake(HandShakeMessage),
    Generic(String),
    LocalEvent(LocalEvent),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum LocalEvent {
    SendEventTo(SocketAddr, Box<Event>),
}

pub const HANDHSHAKE_PATTERN: &str = "NOISE_XX_SHA256";

#[derive(Debug, Serialize, Deserialize)]
pub enum HandShakeMessage {
    Sender(HandShakeSender),
    Responder(HandShakeResponder),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HandShakeSender {
    EphemeralPK([u8; 32]),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HandShakeResponder {
    EphemeralPK([u8; 32]),
    Static(),
}

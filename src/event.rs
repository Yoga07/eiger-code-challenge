use blsttc::{serde, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub enum Event {
    Handshake(HandShakeMessage),
    Generic(String),
}

pub const HANDHSHAKE_PATTERN: &str = "NOISE_XX_SHA256";

#[derive(Debug, Serialize, Deserialize)]
pub enum HandShakeMessage {
    Sender(HandShakeSender),
    Responder(HandShakeResponder),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HandShakeSender {
    EphemeralPK(PublicKey),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum HandShakeResponder {
    EphemeralPK(PublicKey),
    Static(),
}

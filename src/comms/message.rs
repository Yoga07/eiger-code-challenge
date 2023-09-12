use bytes::Bytes;
use crate::comms::Comms;
use crate::comms::error::CommsError;

const HEADER_BYTES_LEN: usize = 8;
const PROTOCOL_VERSION: u16 = 0x0001;

/// Transport layer level messages
pub struct CommsMessage {
    header: Bytes,
    payload: Bytes,
}

impl CommsMessage {
    async fn recv_from_stream(mut recv: quinn::RecvStream) -> Result<Self, CommsError> {
        let mut header_bytes = [0; HEADER_BYTES_LEN];
        recv.read_exact(&mut header_bytes).await.map_err(|e|CommsError::Generic(e.to_string()))?;

        let msg_header = Header::from_bytes(header_bytes);
        let payload_length = msg_header.payload_len() as usize;

        let payload_bytes = recv.read_to_end(payload_length).await?;

        // Assertions
        if payload_bytes.is_empty() {
            return Err(CommsError::PayloadEmpty)
        }



        Ok(CommsMessage {
            header: Bytes::from(header_bytes),
            payload: Bytes::from(payload_bytes),
        })

    }
}

#[derive(Debug)]
struct Header {
    version: u16,
    payload_len: u32,
    #[allow(unused)]
    reserved: [u8; 2],
}

impl Header {
    fn new(payload: Bytes) -> Result<Self, CommsError> {
        let total_len = HEADER_BYTES_LEN + payload.len();
        let _total_len =
            u32::try_from(total_len).map_err(|_| CommsError::MessageTooLarge(total_len))?;

        Ok(Self {
            version: PROTOCOL_VERSION,
            payload_len: payload.len() as u32,
            reserved: [0, 0],
        })
    }

    fn payload_len(&self) -> u32 {
        self.payload_len
    }

    fn to_bytes(&self) -> [u8; HEADER_BYTES_LEN] {
        let version = self.version.to_be_bytes();
        let payload_len = self.payload_len.to_be_bytes();
        [
            version[0],
            version[1],
            payload_len[0],
            payload_len[1],
            payload_len[2],
            payload_len[3],
            0,
            0,
        ]
    }

    fn from_bytes(bytes: [u8; HEADER_BYTES_LEN]) -> Self {
        let version = u16::from_be_bytes([bytes[0], bytes[1]]);
        let user_payload_len = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        Self {
            version,
            payload_len: user_payload_len,
            reserved: [0, 0],
        }
    }
}
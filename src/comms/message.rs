use crate::comms::error::CommsError;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_openssl::SslStream;

const HEADER_BYTES_LEN: usize = 8;
const PROTOCOL_VERSION: u16 = 0x0001;

/// Transport layer level messages
pub struct CommsMessage {
    header: Header,
    payload: Bytes,
}

impl CommsMessage {
    pub(crate) fn new(payload: Bytes) -> Result<Self, CommsError> {
        let header = Header::new(payload.len())?;

        Ok(CommsMessage { header, payload })
    }
    pub(crate) async fn recv_from_stream(mut recv: quinn::RecvStream) -> Result<Self, CommsError> {
        let mut header_bytes = [0; HEADER_BYTES_LEN];
        recv.read_exact(&mut header_bytes)
            .await
            .map_err(|e| CommsError::HeaderRead(e.to_string()))?;

        let msg_header = Header::from_bytes(header_bytes);
        let payload_length = msg_header.payload_len() as usize;

        let payload_bytes = recv
            .read_to_end(payload_length)
            .await
            .map_err(|e| CommsError::RecvFailed(e.to_string()))?;

        // Assertions
        if payload_bytes.is_empty() {
            return Err(CommsError::PayloadEmpty);
        }

        // Received all the bytes required to deser payload
        if payload_bytes.len() != payload_length {
            return Err(CommsError::NotEnoughBytes);
        }

        Ok(CommsMessage {
            header: msg_header,
            payload: Bytes::from(payload_bytes),
        })
    }

    // Helper to write CommsMessage bytes to the provided stream.
    pub(crate) async fn write_to_stream(
        &self,
        send_stream: &mut SslStream<TcpStream>,
    ) -> Result<(), CommsError> {
        // Let's generate the message bytes
        let CommsMessage { header, payload } = self;

        let header_bytes = header.to_bytes();

        let mut all_bytes =
            BytesMut::with_capacity(header_bytes.len() + header.payload_len() as usize);

        all_bytes.extend_from_slice(&header_bytes);
        all_bytes.extend_from_slice(payload);

        // Send bytes of TcpStream
        send_stream
            .write_all(&all_bytes)
            .await
            .map_err(|e| CommsError::SendFailed(e.to_string()))?;

        Ok(())
    }

    pub fn get_payload(&self) -> Bytes {
        self.payload.clone()
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
    fn new(payload_len: usize) -> Result<Self, CommsError> {
        let total_len = HEADER_BYTES_LEN + payload_len;
        let _total_len =
            u32::try_from(total_len).map_err(|_| CommsError::MessageTooLarge(total_len))?;

        Ok(Self {
            version: PROTOCOL_VERSION,
            payload_len: payload_len as u32,
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

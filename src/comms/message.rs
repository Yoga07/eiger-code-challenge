use crate::comms::error::CommsError;
use crate::comms::FramedTransport;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};

/// A thin wrapper over bytes to impl Payload Trait
pub struct CommsMessage {
    payload: Bytes,
}

impl CommsMessage {
    pub(crate) fn new(payload: Bytes) -> Result<Self, CommsError> {
        Ok(CommsMessage { payload })
    }

    // Helper to write CommsMessage bytes to the provided stream.
    pub(crate) async fn write_to_stream(
        &self,
        stream: &mut FramedTransport,
    ) -> Result<(), CommsError> {
        let CommsMessage { payload, .. } = self;

        let (mut writer, mut _reader) = stream.split();

        // Send bytes of TcpStream
        writer
            .send(payload.clone())
            .await
            .map_err(|e| CommsError::SendFailed(e.to_string()))?;

        Ok(())
    }
}

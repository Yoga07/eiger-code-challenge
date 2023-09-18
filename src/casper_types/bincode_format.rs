//! Bincode wire format encoder.
//!
//! An encoder for `Bincode` messages with our specific settings pinned.

use std::{fmt::Debug, io, pin::Pin, sync::Arc};

use crate::casper_types::message::Message;
use bincode::{
    config::{
        RejectTrailing, VarintEncoding, WithOtherEndian, WithOtherIntEncoding, WithOtherLimit,
        WithOtherTrailing,
    },
    Options,
};
use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use tokio_serde::{Deserializer, Serializer};

/// bincode encoder/decoder for messages.
#[allow(clippy::type_complexity)]
pub struct BincodeFormat(
    // Note: `bincode` encodes its options at the type level. The exact shape is determined by
    // `BincodeFormat::default()`.
    pub(crate)  WithOtherTrailing<
        WithOtherIntEncoding<
            WithOtherEndian<
                WithOtherLimit<bincode::DefaultOptions, bincode::config::Infinite>,
                bincode::config::LittleEndian,
            >,
            VarintEncoding,
        >,
        RejectTrailing,
    >,
);

impl BincodeFormat {
    /// Serializes an arbitrary serializable value with the networking bincode serializer.
    #[inline]
    pub(crate) fn serialize_arbitrary<T>(&self, item: &T) -> io::Result<Vec<u8>>
    where
        T: Serialize,
    {
        self.0
            .serialize(item)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }
}

impl Debug for BincodeFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BincodeFormat")
    }
}

impl Default for BincodeFormat {
    fn default() -> Self {
        let opts = bincode::options()
            .with_no_limit() // We rely on framed tokio transports to impose limits.
            .with_little_endian() // Default at the time of this writing, we are merely pinning it.
            .with_varint_encoding() // Same as above.
            .reject_trailing_bytes(); // There is no reason for us not to reject trailing bytes.
        BincodeFormat(opts)
    }
}

impl<P> Serializer<Arc<Message<P>>> for BincodeFormat
where
    Message<P>: Serialize,
{
    type Error = io::Error;

    #[inline]
    fn serialize(self: Pin<&mut Self>, item: &Arc<Message<P>>) -> Result<Bytes, Self::Error> {
        let msg = &**item;
        self.serialize_arbitrary(msg).map(Into::into)
    }
}

impl<P> Deserializer<Message<P>> for BincodeFormat
where
    for<'de> Message<P>: Deserialize<'de>,
{
    type Error = io::Error;

    #[inline]
    fn deserialize(self: Pin<&mut Self>, src: &BytesMut) -> Result<Message<P>, Self::Error> {
        self.0
            .deserialize(src)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
    }
}

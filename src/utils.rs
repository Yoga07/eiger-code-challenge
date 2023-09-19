use datasize::DataSize;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::sha;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Debug, Formatter};
use tracing_appender::rolling::{RollingFileAppender, Rotation};
use tracing_subscriber::{EnvFilter, FmtSubscriber};

mod big_array {
    use serde_big_array::big_array;

    big_array! { BigArray; }
}

/// SHA512 hash.
#[derive(Copy, Clone, DataSize, Deserialize, Serialize)]
pub struct Sha512(#[serde(with = "big_array::BigArray")] [u8; Sha512::SIZE]);

impl Sha512 {
    /// Size of digest in bytes.
    const SIZE: usize = 64;

    /// OpenSSL NID.
    pub const NID: Nid = Nid::SHA512;

    /// Create a new Sha512 by hashing a slice.
    pub fn new<B: AsRef<[u8]>>(data: B) -> Self {
        let mut openssl_sha = sha::Sha512::new();
        openssl_sha.update(data.as_ref());
        Sha512(openssl_sha.finish())
    }

    /// Returns bytestring of the hash, with length `Self::SIZE`.
    fn bytes(&self) -> &[u8] {
        let bs = &self.0[..];

        debug_assert_eq!(bs.len(), Self::SIZE);
        bs
    }

    /// Returns a new OpenSSL `MessageDigest` set to SHA-512.
    pub fn create_message_digest() -> MessageDigest {
        // This can only fail if we specify a `Nid` that does not exist, which cannot happen unless
        // there is something wrong with `Self::NID`.
        MessageDigest::from_nid(Self::NID).expect("Sha512::NID is invalid")
    }
}

// Below are trait implementations for signatures and fingerprints. Both implement the full set of
// traits that are required to stick into either a `HashMap` or `BTreeMap`.
impl PartialEq for Sha512 {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.bytes() == other.bytes()
    }
}

impl Eq for Sha512 {}

impl Ord for Sha512 {
    #[inline]
    fn cmp(&self, other: &Self) -> Ordering {
        Ord::cmp(self.bytes(), other.bytes())
    }
}

impl PartialOrd for Sha512 {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(Ord::cmp(self, other))
    }
}

impl Debug for Sha512 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", base16::encode_lower(&self.0[..]))
    }
}

pub fn setup_logging(to_file: bool) {
    // Configure the tracing subscriber with a filter.
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("trace"))
        .expect("Failed to create filter from default env or 'trace' filter.");

    // Create a custom subscriber that logs to the file.
    let subscriber_builder = FmtSubscriber::builder().with_env_filter(filter);

    if to_file {
        // Create a log file appender that rolls the log file when it reaches a certain size.
        let appender = RollingFileAppender::new(Rotation::HOURLY, "", "eiger_node.log");

        // Set the tracing subscriber as the global subscriber.
        tracing::subscriber::set_global_default(subscriber_builder.with_writer(appender).finish())
            .expect("Failed to set the global tracing subscriber");
    } else {
        // Set the tracing subscriber as the global subscriber.
        tracing::subscriber::set_global_default(subscriber_builder.finish())
            .expect("Failed to set the global tracing subscriber");
    }
}

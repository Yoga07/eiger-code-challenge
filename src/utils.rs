use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use bincode::serialize;
use datasize::DataSize;
use openssl::hash::{DigestBytes, MessageDigest};
use openssl::nid::Nid;
use openssl::sha;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Debug, Display, Formatter};

// pub type Hash = [u8; 32];
//
// pub fn hash(data: &[u8]) -> [u8; 32] {
//     // Create a new SHA-3 (256-bit) hasher
//     let mut hasher = Sha3_256::new();
//
//     // Update the hasher with the input data
//     hasher.update(data);
//
//     // Finalize the hash and return it as a fixed-size array
//     let result = hasher.finalize();
//
//     // Convert the result into a fixed-size array
//     let mut hash_bytes = [0u8; 32];
//     hash_bytes.copy_from_slice(&result[..]);
//
//     hash_bytes
// }

// pub fn serialize_and_encrypt<'a, T: Serialize + Deserialize<'a>>(
//     data: T,
//     cipher: &Aes256Gcm,
//     nonce: &Vec<u8>,
// ) -> Option<Vec<u8>> {
//     let encrypted_data = match serialize(&data) {
//         Ok(serailized_data) => {
//             match cipher.encrypt(GenericArray::from_slice(nonce), serailized_data.as_slice()) {
//                 Ok(enc_data) => enc_data,
//                 Err(e) => {
//                     println!("Error encrypting data {e:?}");
//                     return None;
//                 }
//             }
//         }
//         Err(e) => {
//             println!("Error serializing data {e:?}");
//             return None;
//         }
//     };
//
//     Some(encrypted_data)
// }

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

    /// Converts an OpenSSL digest into an `Sha512`.
    fn from_openssl_digest(digest: &DigestBytes) -> Self {
        let digest_bytes = digest.as_ref();

        debug_assert_eq!(
            digest_bytes.len(),
            Self::SIZE,
            "digest is not the right size - check constants in `tls.rs`"
        );

        let mut buf = [0; Self::SIZE];
        buf.copy_from_slice(&digest_bytes[0..Self::SIZE]);

        Sha512(buf)
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

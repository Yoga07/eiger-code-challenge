use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use bincode::serialize;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub type Hash = [u8; 32];

pub fn hash(data: &[u8]) -> [u8; 32] {
    // Create a new SHA-3 (256-bit) hasher
    let mut hasher = Sha3_256::new();

    // Update the hasher with the input data
    hasher.update(data);

    // Finalize the hash and return it as a fixed-size array
    let result = hasher.finalize();

    // Convert the result into a fixed-size array
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&result[..]);

    hash_bytes
}

pub fn serialize_and_encrypt<'a, T: Serialize + Deserialize<'a>>(
    data: T,
    cipher: &Aes256Gcm,
    nonce: &Vec<u8>,
) -> Option<Vec<u8>> {
    let encrypted_data = match serialize(&data) {
        Ok(serailized_data) => {
            match cipher.encrypt(GenericArray::from_slice(nonce), serailized_data.as_slice()) {
                Ok(enc_data) => enc_data,
                Err(e) => {
                    println!("Error encrypting data {e:?}");
                    return None;
                }
            }
        }
        Err(e) => {
            println!("Error serializing data {e:?}");
            return None;
        }
    };

    Some(encrypted_data)
}

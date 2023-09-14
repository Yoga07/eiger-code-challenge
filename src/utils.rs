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

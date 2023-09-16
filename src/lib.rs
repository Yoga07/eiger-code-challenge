#![allow(dead_code, missing_docs)]

pub mod casper_types;
mod comms;
pub mod error;
pub mod node;
pub mod utils;

pub use crate::comms::CommsError;

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

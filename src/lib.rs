#![allow(dead_code, missing_docs)]

mod comms;
pub mod error;
mod message;
pub mod node;

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

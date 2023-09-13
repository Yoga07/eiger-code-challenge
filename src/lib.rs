#![allow(dead_code, missing_docs)]

mod comms;
pub mod error;
mod event;
mod handshake;
pub mod node;
pub mod utils;

pub use crate::comms::CommsError;
pub use event::Event;

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

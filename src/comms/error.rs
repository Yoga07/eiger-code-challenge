pub enum CommsError {
    PayloadEmpty,
    MessageTooLarge(usize),
    Generic(String),
}
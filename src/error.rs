pub type Result<T> = std::result::Result<T, WrapperError>;

pub enum WrapperError {
    Generic(String),
}

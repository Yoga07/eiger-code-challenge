use openssl::error::ErrorStack;
use rustls::CertificateError;
use std::io;

#[derive(Debug)]
pub enum CommsError {
    HeaderRead(String),
    PayloadEmpty,
    PeerNotFound,
    NotEnoughBytes,
    CertifcateError(String),
    Certificate(CertificateError),
    MessageTooLarge(usize),
    SendFailed(String),
    RecvFailed(String),
    Generic(String),
    BiConnectFailed(String),
    BadCertificate(String),
    Connection(String),
    Io(String),
    Tls(TLSError),
    ListenerCreation(io::Error),
    ListenerSetNonBlocking,
    ListenerConversion,
    CouldNotEncodeOurHandshake(String),
    InvalidRemoteHandshakeMessage(String),
}

#[derive(Debug)]
pub enum TLSError {
    TcpConnection(io::Error),
    TcpNoDelay,
    CouldNotGenerateTLSPK,
    CouldNotGenerateTlsCertificate(ErrorStack),
    CouldNotExtractEcKey,
    TlsInitialization(String),
    TlsHandshake(String),
    NoPeerCertificate,
    PeerCertificateInvalid,
    WrongSignatureAlgorithm,
    CorruptSubjectOrIssuer,
    NotSelfSigned,
    WrongSerialNumber,
    TimeIssue,
    NotYetValid,
    Expired,
    CannotReadPublicKey,
    KeyFailsCheck,
    WrongCurve,
    FailedToValidateSignature,
    InvalidSignature,
    InvalidSerialNumber,
}

impl From<TLSError> for CommsError {
    fn from(value: TLSError) -> Self {
        CommsError::Tls(value)
    }
}

/// OpenSSL result type alias.
///
/// Many functions rely solely on `openssl` functions and return this kind of result.
pub type SslResult<T> = Result<T, ErrorStack>;

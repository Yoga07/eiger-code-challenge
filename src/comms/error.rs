use rustls::CertificateError;

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
}

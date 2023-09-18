use crate::comms::error::{SslResult, TLSError};
use crate::utils::Sha512;
use crate::CommsError;
use datasize::DataSize;
use openssl::asn1::{Asn1Integer, Asn1IntegerRef, Asn1Time};
use openssl::bn::BigNum;
use openssl::ec;
use openssl::ec::EcKey;
use openssl::nid::Nid;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::ssl::{SslContextBuilder, SslVerifyMode, SslVersion};
use openssl::x509::{X509Builder, X509Name, X509NameBuilder, X509NameRef, X509Ref, X509};
use std::cmp::Ordering;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::info;

/// Casper's chosen signature algorithm (**ECDSA  with SHA512**).
const SIGNATURE_ALGORITHM: Nid = Nid::ECDSA_WITH_SHA512;

/// Casper's chosen underlying elliptic curve (**P-521**).
const SIGNATURE_CURVE: Nid = Nid::SECP521R1;

/// Casper's chosen signature algorithm (**SHA512**).
pub const SIGNATURE_DIGEST: Nid = Nid::SHA512;

/// An ephemeral [PKey<Private>] and [TlsCert] that identifies this node
#[derive(DataSize, Debug, Clone)]
pub(crate) struct Identity {
    pub(super) secret_key: Arc<PKey<Private>>,
    pub(super) tls_certificate: Arc<X509>,
    pub(super) network_ca: Option<Arc<X509>>,
}

pub(crate) fn with_generated_certs() -> Result<Identity, CommsError> {
    info!("Generating new keys and certificates");
    let (tls_certificate, secret_key) = generate_node_cert()
        .map_err(|e| CommsError::Tls(TLSError::CouldNotGenerateTlsCertificate(e)))?;

    Ok(Identity {
        secret_key: Arc::new(secret_key),
        tls_certificate: Arc::new(tls_certificate),
        network_ca: None,
    })
}

/// Generates a self-signed (key, certificate) pair suitable for TLS and signing.
///
/// The common name of the certificate will be "casper-node".
pub fn generate_node_cert() -> SslResult<(X509, PKey<Private>)> {
    let private_key = generate_private_key()?;
    let cert = generate_cert(&private_key, "casper-node")?;

    Ok((cert, private_key))
}

/// Generates a secret key suitable for TLS encryption.
pub fn generate_private_key() -> SslResult<PKey<Private>> {
    let ec_group = ec::EcGroup::from_curve_name(SIGNATURE_CURVE)?;
    let ec_key = ec::EcKey::generate(ec_group.as_ref())?;

    PKey::from_ec_key(ec_key)
}

/// Generates a self-signed certificate based on `private_key` with given CN.
fn generate_cert(private_key: &PKey<Private>, cn: &str) -> SslResult<X509> {
    let mut builder = X509Builder::new()?;

    // x509 v3 commonly used, the version is 0-indexed, thus 2 == v3.
    builder.set_version(2)?;

    // The serial number is always one, since we are issuing only one cert.
    builder.set_serial_number(mknum(1)?.as_ref())?;

    let issuer = mkname("US", "Casper Blockchain", cn)?;

    // Set the issuer, subject names, putting the "self" in "self-signed".
    builder.set_issuer_name(issuer.as_ref())?;
    builder.set_subject_name(issuer.as_ref())?;

    let ts = now();
    // We set valid-from to one minute into the past to allow some clock-skew.
    builder.set_not_before(Asn1Time::from_unix(ts - 60)?.as_ref())?;

    // Valid-until is a little under 10 years, missing at least 2 leap days.
    builder.set_not_after(Asn1Time::from_unix(ts + 10 * 365 * 24 * 60 * 60)?.as_ref())?;

    // Set the public key and sign.
    builder.set_pubkey(private_key.as_ref())?;
    assert_eq!(Sha512::NID, SIGNATURE_DIGEST);
    builder.sign(private_key.as_ref(), Sha512::create_message_digest())?;

    let cert = builder.build();

    Ok(cert)
}

pub fn set_context_options(
    ctx: &mut SslContextBuilder,
    cert: &X509Ref,
    private_key: &PKeyRef<Private>,
) -> SslResult<()> {
    ctx.set_min_proto_version(Some(SslVersion::TLS1_3))?;

    ctx.set_certificate(cert)?;
    ctx.set_private_key(private_key)?;
    ctx.check_private_key()?;

    ctx.set_verify_callback(SslVerifyMode::PEER, |_, _| true);

    Ok(())
}

// Ensures that no weaker ciphers have been used to forge a certificate.
pub(crate) fn validate_self_signed_cert(cert: X509) -> Result<X509, TLSError> {
    if cert.signature_algorithm().object().nid() != SIGNATURE_ALGORITHM {
        return Err(TLSError::WrongSignatureAlgorithm);
    }

    let subject =
        name_to_string(cert.subject_name()).map_err(|_| TLSError::CorruptSubjectOrIssuer)?;
    let issuer =
        name_to_string(cert.issuer_name()).map_err(|_| TLSError::CorruptSubjectOrIssuer)?;
    if subject != issuer {
        // All of our certificates are self-signed, so it cannot hurt to check.
        return Err(TLSError::NotSelfSigned);
    }

    // All our certificates have serial number 1.
    if !num_eq(cert.serial_number(), 1).map_err(|_| TLSError::InvalidSerialNumber)? {
        return Err(TLSError::WrongSerialNumber);
    }

    // Check expiration times against current time.
    validate_cert_expiration_date(&cert)?;

    // Ensure that the key is using the correct curve parameters.
    let (public_key, ec_key) = validate_cert_ec_key(&cert)?;
    if ec_key.group().curve_name() != Some(SIGNATURE_CURVE) {
        // The underlying curve is not the one we chose.
        return Err(TLSError::WrongCurve);
    }

    // Finally we can check the actual signature.
    if !cert
        .verify(&public_key)
        .map_err(|_| TLSError::FailedToValidateSignature)?
    {
        return Err(TLSError::InvalidSignature);
    }

    Ok(cert)
}

/// Creates an ASN1 name from string components.
///
/// If `c` or `o` are empty string, they are omitted from the result.
fn mkname(c: &str, o: &str, cn: &str) -> SslResult<X509Name> {
    let mut builder = X509NameBuilder::new()?;

    if !c.is_empty() {
        builder.append_entry_by_text("C", c)?;
    }

    if !o.is_empty() {
        builder.append_entry_by_text("O", o)?;
    }

    builder.append_entry_by_text("CN", cn)?;
    Ok(builder.build())
}

/// Creates an ASN1 integer from a `u32`.
fn mknum(n: u32) -> SslResult<Asn1Integer> {
    let bn = BigNum::from_u32(n)?;

    bn.to_asn1_integer()
}

/// Returns an OpenSSL compatible timestamp.
fn now() -> i64 {
    // Note: We could do the timing dance a little better going straight to the UNIX time functions,
    //       but this saves us having to bring in `libc` as a dependency.
    let now = SystemTime::now();
    let ts: i64 = now
        .duration_since(UNIX_EPOCH)
        // This should work unless the clock is set to before 1970.
        .expect("Great Scott! Your clock is horribly broken, Marty.")
        .as_secs()
        // This will fail past year 2038 on 32 bit systems and very far into the future, both cases
        // we consider out of scope.
        .try_into()
        .expect("32-bit systems and far future are not supported");

    ts
}

/// Converts an `X509NameRef` to a human readable string.
fn name_to_string(name: &X509NameRef) -> SslResult<String> {
    let mut output = String::new();

    for entry in name.entries() {
        output.push_str(entry.object().nid().long_name()?);
        output.push('=');
        output.push_str(entry.data().as_utf8()?.as_ref());
        output.push(' ');
    }

    Ok(output)
}

/// Checks if an `Asn1IntegerRef` is equal to a given u32.
fn num_eq(num: &Asn1IntegerRef, other: u32) -> SslResult<bool> {
    let l = num.to_bn()?;
    let r = BigNum::from_u32(other)?;

    // The `BigNum` API seems to be really lacking here.
    Ok(l.is_negative() == r.is_negative() && l.ucmp(r.as_ref()) == Ordering::Equal)
}

/// Check cert's expiration times against current time.
fn validate_cert_expiration_date(cert: &X509) -> Result<(), TLSError> {
    let asn1_now = Asn1Time::from_unix(now()).map_err(|_| TLSError::TimeIssue)?;
    if asn1_now
        .compare(cert.not_before())
        .map_err(|_| TLSError::TimeIssue)?
        != Ordering::Greater
    {
        return Err(TLSError::NotYetValid);
    }

    if asn1_now
        .compare(cert.not_after())
        .map_err(|_| TLSError::TimeIssue)?
        != Ordering::Less
    {
        return Err(TLSError::Expired);
    }

    Ok(())
}

/// Validate cert's public key, and it's EC key parameters.
fn validate_cert_ec_key(cert: &X509) -> Result<(PKey<Public>, EcKey<Public>), TLSError> {
    let public_key = cert
        .public_key()
        .map_err(|_| TLSError::CannotReadPublicKey)?;
    let ec_key = public_key
        .ec_key()
        .map_err(|_| TLSError::CouldNotExtractEcKey)?;
    ec_key.check_key().map_err(|_| TLSError::KeyFailsCheck)?;
    Ok((public_key, ec_key))
}

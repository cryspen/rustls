use crate::enums::{SignatureAlgorithm, SignatureScheme};
use crate::error::Error;

use pki_types::CertificateDer;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;

/// An abstract signing key.
///
/// This interface is used by rustls to use a private signing key
/// for authentication.  This includes server and client authentication.
pub trait SigningKey: Debug + Send + Sync {
    /// Choose a `SignatureScheme` from those offered.
    ///
    /// Expresses the choice by returning something that implements `Signer`,
    /// using the chosen scheme.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>>;

    /// What kind of key we have.
    fn algorithm(&self) -> SignatureAlgorithm;
}

/// A thing that can sign a message.
pub trait Signer: Debug + Send + Sync {
    /// Signs `message` using the selected scheme.
    ///
    /// `message` is not hashed; the implementer must hash it using the hash function
    /// implicit in [`Self::scheme()`].
    ///
    /// The returned signature format is also defined by [`Self::scheme()`].
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;

    /// Reveals which scheme will be used when you call [`Self::sign()`].
    fn scheme(&self) -> SignatureScheme;
}

/// A packaged-together certificate chain, matching `SigningKey` and
/// optional stapled OCSP response.
#[derive(Clone, Debug)]
pub struct CertifiedKey {
    /// The certificate chain.
    pub cert: Vec<CertificateDer<'static>>,

    /// The certified key.
    pub key: Arc<dyn SigningKey>,

    /// An optional OCSP response from the certificate issuer,
    /// attesting to its continued validity.
    pub ocsp: Option<Vec<u8>>,
}

impl CertifiedKey {
    /// Make a new CertifiedKey, with the given chain and key.
    ///
    /// The cert chain must not be empty. The first certificate in the chain
    /// must be the end-entity certificate.
    pub fn new(cert: Vec<CertificateDer<'static>>, key: Arc<dyn SigningKey>) -> Self {
        Self {
            cert,
            key,
            ocsp: None,
        }
    }

    /// The end-entity certificate.
    pub fn end_entity_cert(&self) -> Result<&CertificateDer<'_>, Error> {
        self.cert
            .first()
            .ok_or(Error::NoCertificatesPresented)
    }
}

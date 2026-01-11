use crate::strongswan::creds::keys::KeyType;
use crate::strongswan::creds::certs::CertType;
use crate::strongswan::creds::certs::x509::X509Flag;

pub mod certs;
pub mod keys;

#[derive(Debug)]
pub enum CredType {
    /// private key, implemented in creds::keys
    PrivateKey{ key_type: KeyType },
    /// public key, implemented in creds::keys
    PublicKey{ key_type: KeyType },
    /// certificates, implemented in creds::certs
    Certificate{ cert_type: CertType },
    /// crypto container, implemented in creds::container
    Container,
}

/// parts to build credentials from
pub struct Builder<'a> {
    /// credential type including subtype
    pub cred_type: &'a CredType,
    /// path to a file encoded in any format
    pub file: Option<String>,
    /// private key ID on a smartcard or TPM
    pub keyid: Option<String>,
    /// enforce additional X.509 flags
    pub x509_flags: Option<X509Flag>,
    /// not valid before (epoch timestamp)
    pub not_before: Option<i64>,
    /// not valid before (epoch timestamp)
    pub not_after: Option<i64>,
    /// CRL distribution points (vector of URIs)
    pub crl_uris:  Option<&'a Vec<String>>,
    /// OCSP AuthorityInfoAccess locations (vector of URIs)
    pub ocsp_uris:  Option<&'a Vec<String>>,
}

impl<'a> Builder<'a> {
    pub fn new(cred_type: &'a CredType) -> Builder<'a> {
        Builder {
            cred_type: cred_type,
            file: None,
            keyid: None,
            x509_flags: None,
            not_before: None,
            not_after: None,
            crl_uris: None,
            ocsp_uris: None,
        }
    }

    pub fn file(self, file: Option<String>) -> Self {
        Builder {
            file: file,
            ..self
        }
    }

    pub fn keyid(self, keyid: Option<String>) -> Self {
        Builder {
            keyid: keyid,
            ..self
        }
    }

     pub fn x509_flags(self, x509_flags: Option<X509Flag>) -> Self {
        Builder {
            x509_flags: x509_flags,
            ..self
        }
    }

    pub fn not_before(self, not_before: Option<i64>) -> Self {
        Builder {
            not_before: not_before,
            ..self
        }
    }

    pub fn not_after(self, not_after: Option<i64>) -> Self {
        Builder {
            not_after: not_after,
            ..self
        }
    }

    pub fn crl_uris(self, crl_uris: Option<&'a Vec<String>>) -> Self {
        Builder {
            crl_uris: crl_uris,
            ..self
        }
    }

    pub fn ocsp_uris(self, ocsp_uris: Option<&'a Vec<String>>) -> Self {
        Builder {
            ocsp_uris: ocsp_uris,
            ..self
        }
    }

    pub fn build(self) -> bool {
        println!("{:?}", self.cred_type);

        if self.file != None {
            println!("  file: {}", self.file.unwrap());
        }
        if self.keyid != None {
            println!("  keyid: {}", self.keyid.unwrap());
        }
        if self.x509_flags != None {
            println!("  x509_flags: 0b{:0>11b}", self.x509_flags.unwrap());
        }
        if self.not_before != None {
            println!("  not_before: {}", self.not_before.unwrap());
        }
        if self.not_after != None {
            println!("  not_after:  {}", self.not_after.unwrap());
        }
        if self.crl_uris != None {
            println!("  crl_uris:");
            for u in self.crl_uris.unwrap()
            {
                println!("    {}", u);
            }
        }
        if self.ocsp_uris != None {
            println!("  ocsp_uris:");
            for u in self.ocsp_uris.unwrap()
            {
                println!("    {}", u);
            }
        }

        return true;
    }
}

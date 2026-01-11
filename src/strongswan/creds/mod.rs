pub mod certs;
pub mod keys;

#[derive(Debug)]
pub enum CredType {
    /// private key, implemented in creds::keys
    PrivateKey,
    /// public key, implemented in creds::keys
    PublicKey,
    /// certificates, implemented in creds::certs
    Certificate,
    /// crypto container, implemented in creds::container
    Container,
}
